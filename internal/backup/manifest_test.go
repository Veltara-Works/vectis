package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManifest_LoadEmpty(t *testing.T) {
	dir := t.TempDir()
	m, err := LoadManifest(dir)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if len(m.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(m.Entries))
	}
}

func TestManifest_AddAndSave(t *testing.T) {
	dir := t.TempDir()
	m, _ := LoadManifest(dir)

	entry := ManifestEntry{
		ID:        "full-1",
		Type:      BackupFull,
		Path:      "/backups/full-1.tar.gz",
		Size:      1024,
		CreatedAt: time.Now().UTC(),
	}
	if err := m.Add(entry); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Reload and verify.
	m2, err := LoadManifest(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(m2.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(m2.Entries))
	}
	if m2.Entries[0].ID != "full-1" {
		t.Errorf("ID = %q, want full-1", m2.Entries[0].ID)
	}
}

func TestManifest_LastFull(t *testing.T) {
	dir := t.TempDir()
	m, _ := LoadManifest(dir)

	if m.LastFull() != nil {
		t.Fatal("expected nil LastFull on empty manifest")
	}

	m.Add(ManifestEntry{ID: "full-1", Type: BackupFull, Path: "a", CreatedAt: time.Now()})
	m.Add(ManifestEntry{ID: "incr-1", Type: BackupIncremental, ParentID: "full-1", Path: "b", CreatedAt: time.Now()})
	m.Add(ManifestEntry{ID: "full-2", Type: BackupFull, Path: "c", CreatedAt: time.Now()})

	last := m.LastFull()
	if last == nil || last.ID != "full-2" {
		t.Errorf("LastFull = %v, want full-2", last)
	}
}

func TestManifest_IncrementalsSince(t *testing.T) {
	dir := t.TempDir()
	m, _ := LoadManifest(dir)

	now := time.Now()
	m.Add(ManifestEntry{ID: "full-1", Type: BackupFull, Path: "a", CreatedAt: now})
	m.Add(ManifestEntry{ID: "incr-1", Type: BackupIncremental, ParentID: "full-1", Path: "b", CreatedAt: now.Add(1 * time.Hour)})
	m.Add(ManifestEntry{ID: "incr-2", Type: BackupIncremental, ParentID: "full-1", Path: "c", CreatedAt: now.Add(2 * time.Hour)})
	m.Add(ManifestEntry{ID: "incr-other", Type: BackupIncremental, ParentID: "full-99", Path: "d", CreatedAt: now.Add(3 * time.Hour)})

	incrs := m.IncrementalsSince("full-1")
	if len(incrs) != 2 {
		t.Fatalf("expected 2 incrementals, got %d", len(incrs))
	}
	if incrs[0].ID != "incr-1" || incrs[1].ID != "incr-2" {
		t.Errorf("wrong order: %s, %s", incrs[0].ID, incrs[1].ID)
	}
}

func TestManifest_ChainDepth(t *testing.T) {
	dir := t.TempDir()
	m, _ := LoadManifest(dir)

	m.Add(ManifestEntry{ID: "full-1", Type: BackupFull, Path: "a", CreatedAt: time.Now()})
	if m.ChainDepth() != 0 {
		t.Errorf("depth = %d, want 0", m.ChainDepth())
	}

	m.Add(ManifestEntry{ID: "incr-1", Type: BackupIncremental, ParentID: "full-1", Path: "b", CreatedAt: time.Now()})
	m.Add(ManifestEntry{ID: "incr-2", Type: BackupIncremental, ParentID: "full-1", Path: "c", CreatedAt: time.Now()})
	if m.ChainDepth() != 2 {
		t.Errorf("depth = %d, want 2", m.ChainDepth())
	}
}

func TestManifest_RestoreChain(t *testing.T) {
	dir := t.TempDir()
	m, _ := LoadManifest(dir)

	if m.RestoreChain() != nil {
		t.Error("expected nil chain on empty manifest")
	}

	now := time.Now()
	m.Add(ManifestEntry{ID: "full-1", Type: BackupFull, Path: "a", CreatedAt: now})
	m.Add(ManifestEntry{ID: "incr-1", Type: BackupIncremental, ParentID: "full-1", Path: "b", CreatedAt: now.Add(time.Hour)})

	chain := m.RestoreChain()
	if len(chain) != 2 {
		t.Fatalf("chain length = %d, want 2", len(chain))
	}
	if chain[0].ID != "full-1" || chain[1].ID != "incr-1" {
		t.Errorf("chain = %s, %s", chain[0].ID, chain[1].ID)
	}
}

func TestManifest_Prune(t *testing.T) {
	dir := t.TempDir()

	// Create a real file for one entry.
	realFile := filepath.Join(dir, "real.tar.gz")
	os.WriteFile(realFile, []byte("data"), 0600)

	m, _ := LoadManifest(dir)
	m.Add(ManifestEntry{ID: "full-1", Type: BackupFull, Path: realFile, CreatedAt: time.Now()})
	m.Add(ManifestEntry{ID: "full-gone", Type: BackupFull, Path: "/nonexistent/gone.tar.gz", CreatedAt: time.Now()})
	m.Add(ManifestEntry{ID: "incr-orphan", Type: BackupIncremental, ParentID: "full-gone", Path: realFile, CreatedAt: time.Now()})

	removed := m.Prune()
	if removed != 2 {
		t.Errorf("removed = %d, want 2 (full-gone + incr-orphan)", removed)
	}
	if len(m.Entries) != 1 {
		t.Errorf("remaining = %d, want 1", len(m.Entries))
	}
}
