package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// BackupType distinguishes full and incremental backups.
type BackupType string

const (
	BackupFull        BackupType = "full"
	BackupIncremental BackupType = "incremental"
)

// ManifestEntry records one backup in the chain.
type ManifestEntry struct {
	ID        string     `json:"id"`
	Type      BackupType `json:"type"`
	Path      string     `json:"path"`
	ParentID  string     `json:"parent_id,omitempty"` // points to the full backup this incremental depends on
	Size      int64      `json:"size"`
	CreatedAt time.Time  `json:"created_at"`
}

// Manifest tracks the full→incremental backup chain.
type Manifest struct {
	Entries []ManifestEntry `json:"entries"`
	path    string
}

// LoadManifest reads the manifest from disk. Returns an empty manifest if the
// file does not exist.
func LoadManifest(backupDir string) (*Manifest, error) {
	p := filepath.Join(backupDir, "manifest.json")
	m := &Manifest{path: p}

	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	if err := json.Unmarshal(data, m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	m.path = p
	return m, nil
}

// Save writes the manifest to disk atomically.
func (m *Manifest) Save() error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	tmpPath := m.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	if err := os.Rename(tmpPath, m.path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename manifest: %w", err)
	}
	return nil
}

// Add appends an entry and saves.
func (m *Manifest) Add(entry ManifestEntry) error {
	m.Entries = append(m.Entries, entry)
	return m.Save()
}

// LastFull returns the most recent full backup, or nil if none exists.
func (m *Manifest) LastFull() *ManifestEntry {
	for i := len(m.Entries) - 1; i >= 0; i-- {
		if m.Entries[i].Type == BackupFull {
			return &m.Entries[i]
		}
	}
	return nil
}

// IncrementalsSince returns all incremental entries whose ParentID matches
// the given full backup ID, ordered by creation time.
func (m *Manifest) IncrementalsSince(fullID string) []ManifestEntry {
	var result []ManifestEntry
	for _, e := range m.Entries {
		if e.Type == BackupIncremental && e.ParentID == fullID {
			result = append(result, e)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result
}

// ChainDepth returns how many incrementals exist since the last full.
func (m *Manifest) ChainDepth() int {
	lastFull := m.LastFull()
	if lastFull == nil {
		return 0
	}
	return len(m.IncrementalsSince(lastFull.ID))
}

// RestoreChain returns the full backup entry plus all subsequent incrementals
// needed to restore to the latest state. Returns nil if no full backup exists.
func (m *Manifest) RestoreChain() []ManifestEntry {
	lastFull := m.LastFull()
	if lastFull == nil {
		return nil
	}
	chain := []ManifestEntry{*lastFull}
	chain = append(chain, m.IncrementalsSince(lastFull.ID)...)
	return chain
}

// Prune removes entries for files that no longer exist on disk and
// removes orphaned incrementals whose parent full has been deleted.
func (m *Manifest) Prune() int {
	kept := make([]ManifestEntry, 0, len(m.Entries))
	removed := 0

	// First pass: keep entries whose files exist.
	fullIDs := make(map[string]bool)
	for _, e := range m.Entries {
		if _, err := os.Stat(e.Path); err != nil {
			removed++
			continue
		}
		if e.Type == BackupFull {
			fullIDs[e.ID] = true
		}
		kept = append(kept, e)
	}

	// Second pass: remove incrementals whose parent full was pruned.
	final := make([]ManifestEntry, 0, len(kept))
	for _, e := range kept {
		if e.Type == BackupIncremental && !fullIDs[e.ParentID] {
			removed++
			continue
		}
		final = append(final, e)
	}

	m.Entries = final
	return removed
}
