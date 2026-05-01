package orchestrator

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// ConfigFile captures one rendered config file, ready to be written under a
// generated-configs root (e.g. /var/vectis/generated). RelPath is relative to
// that root — e.g. "postfix/main.cf" or "rspamd/local.lua".
//
// Mirrors engine.GeneratedFile so the orchestrator package can stay decoupled
// from internal/engine without re-importing it.
type ConfigFile struct {
	RelPath string
	Content []byte
	Mode    os.FileMode // zero = use 0600
}

// ConfigGenerator returns the full set of rendered service config files for
// the given release tag. Empty releaseTag means "use whatever Version is baked
// into the orchestrator binary".
//
// Used by self-heal to reconcile structural drift across ALL service configs
// (postfix/dovecot/rspamd/traefik/...), not just docker-compose.yml. This is
// what closes the v0.1.0 → v0.1.5 prod walk gap where the install-time
// generated dir carries stale configs whose structural shape no longer matches
// the running binary's templates (named-volume layouts, legacy traefik-acme
// path, missing rspamd files, etc.).
//
// Should NOT include docker-compose.yml — that has its own generator
// (ComposeGenerator) and writes to a different path (/etc/vectis/...).
type ConfigGenerator func(ctx context.Context, releaseTag string) ([]ConfigFile, error)

// RegenerateConfigs renders the full per-service config set via the supplied
// ConfigGenerator and reconciles each file against on-disk content under
// generatedDir. For every drifted file, the existing on-disk content is mirrored
// into backupDir (preserving rel-path structure) before the new content is
// atomically written.
//
// Returns:
//   - rewritten = true if at least one file was changed (created or replaced).
//   - changed   = the rel-paths of files written, in template-walk order.
//     Useful for log lines and for downstream "do we need to recreate
//     containers" decisions.
//   - err       = non-nil iff generation, read, or write failed. On error the
//     filesystem may be partially modified; caller should treat backupDir as
//     authoritative for restore.
//
// If no drift is detected the backup directory is left empty and rolled up
// (removed) — keeps the snapshots tree clean.
//
// Files present on disk but absent from the template set are left alone —
// removing them is more invasive than this self-heal pass should ever be.
// Compose no longer references them so they're inert; explicit cleanup can
// happen in a later release.
func RegenerateConfigs(
	ctx context.Context,
	generatedDir, backupDir, releaseTag string,
	gen ConfigGenerator,
) (bool, []string, error) {
	if gen == nil {
		return false, nil, fmt.Errorf("config generator not configured")
	}

	files, err := gen(ctx, releaseTag)
	if err != nil {
		return false, nil, fmt.Errorf("generate configs: %w", err)
	}
	if len(files) == 0 {
		return false, nil, nil
	}

	var changed []string
	var pendingBackups []struct {
		relPath string
		oldData []byte
		oldMode os.FileMode
	}
	var pendingWrites []ConfigFile

	for _, f := range files {
		if f.RelPath == "" {
			return false, nil, fmt.Errorf("generator returned file with empty RelPath")
		}
		// Compose lives at /etc/vectis, never under generatedDir; if a
		// caller wires a generator that incorrectly emits it, refuse rather
		// than silently scribbling on the wrong path.
		if f.RelPath == "docker-compose.yml" {
			return false, nil, fmt.Errorf(
				"generator returned docker-compose.yml — that file is owned by RegenerateCompose, not RegenerateConfigs")
		}

		fullPath := filepath.Join(generatedDir, f.RelPath)
		existing, readErr := os.ReadFile(fullPath)
		switch {
		case readErr == nil:
			if bytes.Equal(existing, f.Content) {
				continue // unchanged
			}
			// Preserve the existing file's mode so a restored shell script
			// (e.g. postgres/init-users.sh, currently the only executable
			// in the template set) keeps its 0755 bit.
			info, statErr := os.Stat(fullPath)
			oldMode := os.FileMode(0o644)
			if statErr == nil {
				oldMode = info.Mode() & os.ModePerm
			}
			pendingBackups = append(pendingBackups, struct {
				relPath string
				oldData []byte
				oldMode os.FileMode
			}{f.RelPath, existing, oldMode})
			pendingWrites = append(pendingWrites, f)
			changed = append(changed, f.RelPath)
		case os.IsNotExist(readErr):
			// New file — no backup needed (rollback = delete), but still
			// counted as a change so callers know to recreate.
			pendingWrites = append(pendingWrites, f)
			changed = append(changed, f.RelPath)
		default:
			return false, nil, fmt.Errorf("read existing %s: %w", f.RelPath, readErr)
		}
	}

	if len(changed) == 0 {
		return false, nil, nil
	}

	// Materialise backups first so a partial write still has a recovery path.
	for _, b := range pendingBackups {
		bPath := filepath.Join(backupDir, b.relPath)
		if err := writeAtomicFile(bPath, b.oldData, b.oldMode); err != nil {
			return false, nil, fmt.Errorf("backup %s: %w", b.relPath, err)
		}
	}

	for _, f := range pendingWrites {
		mode := f.Mode
		if mode == 0 {
			mode = 0o600
		}
		fullPath := filepath.Join(generatedDir, f.RelPath)
		if err := writeAtomicFile(fullPath, f.Content, mode); err != nil {
			return true, changed, fmt.Errorf("write %s: %w", f.RelPath, err)
		}
	}

	return true, changed, nil
}

// RestoreConfigsBackup walks backupDir and copies every file back into
// generatedDir at the same rel-path. Used by self-heal when the post-regen
// service recreate fails and we need to put the pre-self-heal config state
// back in place.
//
// Files that were created brand-new by RegenerateConfigs (and therefore have
// no entry in backupDir) are removed from generatedDir so the disk truly
// returns to the pre-regen state. Caller passes the list of newly-created
// rel-paths via the createdNewFiles slice.
//
// If backupDir doesn't exist (no rewrites happened, or the backup was rolled
// up), this is a no-op apart from any createdNewFiles cleanup.
func RestoreConfigsBackup(generatedDir, backupDir string, createdNewFiles []string) error {
	for _, rel := range createdNewFiles {
		// A new file has no backup; remove it to undo creation.
		_ = os.Remove(filepath.Join(generatedDir, rel))
	}

	stat, err := os.Stat(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat backup dir: %w", err)
	}
	if !stat.IsDir() {
		return fmt.Errorf("backup path %s is not a directory", backupDir)
	}

	return filepath.Walk(backupDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(backupDir, path)
		if err != nil {
			return fmt.Errorf("rel-path for %s: %w", path, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read backup %s: %w", rel, err)
		}
		if err := writeAtomicFile(filepath.Join(generatedDir, rel), data, info.Mode()&os.ModePerm); err != nil {
			return fmt.Errorf("restore %s: %w", rel, err)
		}
		return nil
	})
}
