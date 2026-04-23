package orchestrator

import (
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
	if err := writeAtomicFile(backupPath, content, 0o644); err != nil {
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

	if err := writeAtomicFile(composePath, []byte(rewritten), 0o644); err != nil {
		return false, fmt.Errorf("write rewritten compose: %w", err)
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
	if err := writeAtomicFile(composePath, data, 0o644); err != nil {
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
