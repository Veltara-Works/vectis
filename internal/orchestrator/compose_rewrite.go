package orchestrator

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// RewriteComposeTags applies the desired image tags from plan changes to the
// compose file on disk. For each PlanChange with OldImage and NewImage set,
// it finds the `image:` line carrying OldImage and rewrites it to NewImage.
//
// Before writing, the original file content is saved to backupPath so
// rollback can restore the exact pre-Apply bytes regardless of any other
// edits that might happen during the Apply window. If no changes need to
// be applied (every target already matches), the backup is removed again
// so rollback doesn't pointlessly restore an identical file.
//
// Only the first occurrence of each OldImage is replaced, matching the
// compose template's invariant that every service has a unique image ref.
// OldImage must appear at the start of an `image:` line's value — substring
// or comment matches are ignored.
//
// Returns:
//   - (true, nil)  = rewrite happened, backup is at backupPath
//   - (false, nil) = no rewrite needed, backup deleted
//   - (_, err)     = read/write error; compose file left untouched unless
//     already partially rewritten (rare; see comment inline)
func RewriteComposeTags(composePath string, changes []PlanChange, backupPath string) (bool, error) {
	content, err := os.ReadFile(composePath)
	if err != nil {
		return false, fmt.Errorf("read compose: %w", err)
	}

	// Always write the backup first, so rollback has a restoration target
	// even if the rewrite partially completes and then fails mid-flight.
	// The compose file and its backups bake in DB superuser + service-role
	// passwords, so all writes here use 0600 rather than world-readable 0644
	// (audit E-L1) — root reads them anyway.
	if err := writeAtomicFile(backupPath, content, 0o600); err != nil {
		return false, fmt.Errorf("backup compose: %w", err)
	}

	rewritten := string(content)
	replacements := 0
	for _, ch := range changes {
		if ch.OldImage == "" || ch.NewImage == "" || ch.OldImage == ch.NewImage {
			continue
		}
		// Match `  image: <OldImage>` on its own line, preserving the leading
		// whitespace so the diff is one-line-in-one-line-out.
		pattern := regexp.MustCompile(
			`(?m)^([ \t]*image:[ \t]*)` + regexp.QuoteMeta(ch.OldImage) + `[ \t]*$`,
		)
		matches := pattern.FindAllStringIndex(rewritten, -1)
		if len(matches) == 0 {
			continue
		}
		rewritten = pattern.ReplaceAllString(rewritten, "${1}"+ch.NewImage)
		replacements += len(matches)
	}

	if replacements == 0 {
		// Nothing needed rewriting. Clean up the backup we just wrote —
		// rollback reading a backup identical to the current file is
		// harmless but misleading when debugging.
		_ = os.Remove(backupPath)
		return false, nil
	}

	if err := writeAtomicFile(composePath, []byte(rewritten), 0o600); err != nil {
		return false, fmt.Errorf("write rewritten compose: %w", err)
	}
	return true, nil
}

// composeVectisImageLineRe matches a compose `image:` line for a vectis-* image,
// capturing: (1) the `image:` prefix incl. leading whitespace, (2) the bare
// repository (ghcr.io/.../vectis-<svc>), (3) the service segment, (4) the tag
// (":v0.1.42", optional), (5) an existing digest ("@sha256:…", optional).
var composeVectisImageLineRe = regexp.MustCompile(
	`(?m)^([ \t]*image:[ \t]*)(` + regexp.QuoteMeta(releaseServicePrefix) + `([a-z0-9-]+))(:[^@\s]+)?(@sha256:[0-9a-f]{64})?[ \t]*$`,
)

// pinComposeImageDigests rewrites each vectis-* `image:` line in a compose file
// to carry the manifest digest for its service (REL-3): `…/vectis-api:tag` (or a
// stale `…@sha256:old`) becomes `…/vectis-api:tag@sha256:<digest>`. Idempotent,
// and a no-op for services absent from the map — so a partial manifest pins what
// it can and leaves the rest tag-only. Returns compose unchanged when digests is
// empty (the graceful-degradation path). Operates on the rendered bytes, so it
// composes with any renderer (embedded templates or render-from-target).
func pinComposeImageDigests(compose []byte, digests map[string]string) []byte {
	if len(digests) == 0 {
		return compose
	}
	return []byte(composeVectisImageLineRe.ReplaceAllStringFunc(string(compose), func(line string) string {
		m := composeVectisImageLineRe.FindStringSubmatch(line)
		prefix, repo, svc, tag := m[1], m[2], m[3], m[4]
		dig, ok := digests[svc]
		if !ok {
			return line // no digest published for this service — leave it as rendered.
		}
		return prefix + repo + tag + "@" + dig
	}))
}

// extractComposeImageDigests reads the digest currently pinned to each vectis-*
// service from a compose file — the inverse of pinComposeImageDigests. Self-heal
// uses it to preserve the digests already on disk when it regenerates the compose
// from templates (which render images by tag only), so drift-correction never
// silently un-pins the images. Returns nil when no vectis image carries a digest
// (e.g. a pre-REL-3 install), which pins nothing.
func extractComposeImageDigests(compose []byte) map[string]string {
	out := map[string]string{}
	for _, m := range composeVectisImageLineRe.FindAllStringSubmatch(string(compose), -1) {
		svc, digest := m[3], m[5]
		if digest != "" {
			out[svc] = strings.TrimPrefix(digest, "@")
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// RegenerateCompose re-renders the docker-compose.yml from the embedded
// templates via the supplied ComposeGenerator and atomically writes the
// result to composePath, after first backing up the current on-disk content
// to backupPath so rollback can restore the exact pre-Apply bytes.
//
// Unlike RewriteComposeTags, this picks up structural template changes
// (new bind mounts, new services, env tweaks, etc.) — not just `image:`
// tag bumps. Required for v0.1.2's per-domain spam mounts to land on
// upgrade without manual host-side compose patching.
//
// Returns:
//   - (true, nil)  = generated content differed from on-disk; backup is at
//     backupPath, compose has been rewritten.
//   - (false, nil) = generated content matched on-disk byte-for-byte;
//     backup deleted (no rollback restore needed).
//   - (_, err)     = compose left untouched if read/gen failed; partial
//     state possible only if the atomic-rename itself failed mid-flight,
//     in which case the backup is on disk and rollback can restore it.
//
// CROSS-VERSION CAVEAT: This regenerates against the orchestrator binary's
// embedded templates. On an Apply that bumps the orchestrator itself, the
// regen runs under the OLD orchestrator process — so any template changes
// shipped in the NEW release won't land until the FOLLOWING Apply. To pick
// up new structural changes on a multi-version jump, walk the upgrade in
// two steps (vN → vN+1, then vN+1 → vN+2).
func RegenerateCompose(
	ctx context.Context,
	composePath, backupPath, releaseTag string,
	gen ComposeGenerator,
	imageDigests map[string]string,
) (bool, error) {
	if gen == nil {
		return false, fmt.Errorf("compose generator not configured")
	}

	current, err := os.ReadFile(composePath)
	if err != nil {
		return false, fmt.Errorf("read compose: %w", err)
	}

	// Always write the backup first so rollback has a restoration target
	// even if the rewrite fails midway through atomic-rename.
	if err := writeAtomicFile(backupPath, current, 0o600); err != nil {
		return false, fmt.Errorf("backup compose: %w", err)
	}

	generated, err := gen(ctx, releaseTag)
	if err != nil {
		_ = os.Remove(backupPath)
		return false, fmt.Errorf("generate compose: %w", err)
	}
	if len(generated) == 0 {
		_ = os.Remove(backupPath)
		return false, fmt.Errorf("generated compose is empty")
	}

	// Pin vectis-* images to the signed manifest's digests (REL-3). The generator
	// renders images by tag (`:{{ .Version }}`); this splices in `@sha256:…` so
	// the recreate runs exactly the bytes the manifest names — regardless of
	// which renderer produced the compose (embedded templates or the target
	// image's own `vectis config generate`). No-op when imageDigests is empty
	// (manifest carried no digests → tag-only pin). Done before the bytes.Equal
	// check below so the no-op / backup lifecycle accounts for the pinned form.
	generated = pinComposeImageDigests(generated, imageDigests)

	if bytes.Equal(current, generated) {
		// No-op: content matches. Drop the backup so a later rollback
		// doesn't pointlessly restore an identical file.
		_ = os.Remove(backupPath)
		return false, nil
	}

	if err := writeAtomicFile(composePath, generated, 0o600); err != nil {
		return false, fmt.Errorf("write regenerated compose: %w", err)
	}
	return true, nil
}

// RestoreComposeBackup puts the pre-Apply compose file back in place. Used by
// rollback after the database restore so the subsequent compose-up picks up
// the old tags. If backupPath doesn't exist, this is a no-op (Apply never
// got as far as rewriting, or rewrite reported "no changes").
func RestoreComposeBackup(composePath, backupPath string) error {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read compose backup: %w", err)
	}
	if err := writeAtomicFile(composePath, data, 0o600); err != nil {
		return fmt.Errorf("restore compose: %w", err)
	}
	return nil
}

// composeBackupPathFor derives a compose-file backup path from a pg_dump
// snapshot path so the two stay colocated and share a fate (same timestamp,
// same directory). e.g. /var/vectis/snapshots/pre-update-2026-04-23T10-00.sql
// becomes /var/vectis/snapshots/pre-update-2026-04-23T10-00-compose.yml.
func composeBackupPathFor(snapshotPath string) string {
	ext := filepath.Ext(snapshotPath)
	base := strings.TrimSuffix(snapshotPath, ext)
	return base + "-compose.yml"
}

// configBackupDirFor derives a per-snapshot configs-backup directory path
// colocated with the snapshot + compose backup so rollback finds them all
// together. RegenerateConfigs writes per-service config backups under this
// dir during Apply Phase 3.6; doRollback restores from it on Apply failure.
//
// For snapshot /var/vectis/snapshots/pre-update-XYZ.sql this returns
// /var/vectis/snapshots/pre-update-XYZ-configs/.
func configBackupDirFor(snapshotPath string) string {
	ext := filepath.Ext(snapshotPath)
	base := strings.TrimSuffix(snapshotPath, ext)
	return base + "-configs"
}

// writeAtomicFile writes data to path via a tmp file + rename so readers
// never observe a partial file. Shared with the compose rewriter.
func writeAtomicFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
