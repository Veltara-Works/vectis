package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SnapshotManager handles pg_dump snapshot creation and restoration.
// Snapshots are plain-SQL files stored under Config.SnapshotDir.
type SnapshotManager struct {
	cfg    Config
	logger *slog.Logger
}

// NewSnapshotManager creates a SnapshotManager.
func NewSnapshotManager(cfg Config, logger *slog.Logger) *SnapshotManager {
	return &SnapshotManager{
		cfg:    cfg,
		logger: logger,
	}
}

// SnapshotInfo describes a snapshot file on disk.
type SnapshotInfo struct {
	Path      string    `json:"path"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateSnapshot runs pg_dump and writes the output to a timestamped SQL file
// under the configured snapshot directory. Returns the full path of the snapshot.
func (sm *SnapshotManager) CreateSnapshot(ctx context.Context) (string, error) {
	// Ensure the snapshot directory exists.
	if err := os.MkdirAll(sm.cfg.SnapshotDir, 0700); err != nil {
		return "", fmt.Errorf("create snapshot directory %s: %w", sm.cfg.SnapshotDir, err)
	}

	timestamp := time.Now().UTC().Format("20060102-150405")
	filename := fmt.Sprintf("pre-update-%s.sql", timestamp)
	snapshotPath := filepath.Join(sm.cfg.SnapshotDir, filename)

	sm.logger.Info("creating database snapshot",
		"path", snapshotPath,
		"database", sm.cfg.DBName,
		"host", sm.cfg.DBHost,
	)

	// Build pg_dump command. We use --clean so the dump can be restored onto
	// an existing database (drops objects before re-creating them).
	args := []string{
		"--host", sm.cfg.DBHost,
		"--port", fmt.Sprintf("%d", sm.cfg.DBPort),
		"--username", sm.cfg.DBUser,
		"--dbname", sm.cfg.DBName,
		"--no-password",
		"--clean",
		"--if-exists",
		"--file", snapshotPath,
	}

	cmd := exec.CommandContext(ctx, "pg_dump", args...)
	// Supply the password via PGPASSWORD environment variable.
	cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", sm.cfg.DBPassword))

	output, err := cmd.CombinedOutput()
	if err != nil {
		sm.logger.Error("pg_dump failed",
			"error", err,
			"output", string(output),
		)
		return "", fmt.Errorf("pg_dump failed: %w: %s", err, string(output))
	}

	// Verify the file was created and is non-empty.
	info, err := os.Stat(snapshotPath)
	if err != nil {
		return "", fmt.Errorf("stat snapshot file: %w", err)
	}
	if info.Size() == 0 {
		return "", fmt.Errorf("snapshot file is empty: %s", snapshotPath)
	}

	sm.logger.Info("snapshot created",
		"path", snapshotPath,
		"size_bytes", info.Size(),
	)

	return snapshotPath, nil
}

// RestoreSnapshot restores a database from a snapshot file using psql.
// This drops existing objects (via --clean in the dump) and re-creates them.
func (sm *SnapshotManager) RestoreSnapshot(ctx context.Context, snapshotPath string) error {
	// Verify the snapshot file exists.
	if _, err := os.Stat(snapshotPath); err != nil {
		return fmt.Errorf("snapshot file not found: %w", err)
	}

	sm.logger.Info("restoring database from snapshot",
		"path", snapshotPath,
		"database", sm.cfg.DBName,
	)

	args := []string{
		"--host", sm.cfg.DBHost,
		"--port", fmt.Sprintf("%d", sm.cfg.DBPort),
		"--username", sm.cfg.DBUser,
		"--dbname", sm.cfg.DBName,
		"--no-password",
		"--single-transaction",
		"--file", snapshotPath,
	}

	cmd := exec.CommandContext(ctx, "psql", args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", sm.cfg.DBPassword))

	output, err := cmd.CombinedOutput()
	if err != nil {
		sm.logger.Error("psql restore failed",
			"error", err,
			"output", string(output),
		)
		return fmt.Errorf("psql restore failed: %w: %s", err, string(output))
	}

	sm.logger.Info("snapshot restored", "path", snapshotPath)
	return nil
}

// ListSnapshots returns all snapshot files in the snapshot directory, sorted
// by modification time (newest first).
func (sm *SnapshotManager) ListSnapshots() ([]SnapshotInfo, error) {
	entries, err := os.ReadDir(sm.cfg.SnapshotDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No snapshots directory yet.
		}
		return nil, fmt.Errorf("read snapshot directory: %w", err)
	}

	var snapshots []SnapshotInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			sm.logger.Warn("failed to stat snapshot file", "name", entry.Name(), "error", err)
			continue
		}

		snapshots = append(snapshots, SnapshotInfo{
			Path:      filepath.Join(sm.cfg.SnapshotDir, entry.Name()),
			Name:      entry.Name(),
			Size:      info.Size(),
			CreatedAt: info.ModTime(),
		})
	}

	// Sort newest first.
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].CreatedAt.After(snapshots[j].CreatedAt)
	})

	return snapshots, nil
}
