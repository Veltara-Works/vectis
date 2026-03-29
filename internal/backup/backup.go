package backup

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// Config holds the backup manager configuration.
type Config struct {
	BackupDir   string // default /var/vectis/backups
	MailDataDir string // default /var/vectis/mail
	DKIMDir     string // default /var/vectis/dkim
	ConfigDir   string // default /etc/vectis
	SnapshotDir string // default /var/vectis/snapshots

	// Database connection settings for pg_dump/psql.
	DBHost     string
	DBPort     int
	DBName     string
	DBUser     string
	DBPassword string

	// Docker compose path for stopping/starting services.
	ComposePath string
}

// DefaultConfig returns a Config with production defaults.
func DefaultConfig() Config {
	return Config{
		BackupDir:   "/var/vectis/backups",
		MailDataDir: "/var/vectis/mail",
		DKIMDir:     "/var/vectis/dkim",
		ConfigDir:   "/etc/vectis",
		SnapshotDir: "/var/vectis/snapshots",
		DBHost:      "postgres",
		DBPort:      5432,
		DBName:      "vectis",
		DBUser:      "vectis_api",
		ComposePath: "/etc/vectis/docker-compose.yml",
	}
}

// Manager handles backup creation and restoration.
type Manager struct {
	db     *pgxpool.Pool
	logger *slog.Logger
	cfg    Config
	repo   *repository.BackupRepo
}

// NewManager creates a new backup Manager.
func NewManager(db *pgxpool.Pool, logger *slog.Logger, cfg Config) *Manager {
	return &Manager{
		db:     db,
		logger: logger,
		cfg:    cfg,
		repo:   repository.NewBackupRepo(db),
	}
}

// BackupInfo describes a backup archive on disk.
type BackupInfo struct {
	Path      string    `json:"path"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

// Create creates a full backup. It dumps the database, archives mail data,
// config files, and DKIM keys into a single tar.gz archive. Progress is tracked
// in the backup_jobs table. The backup runs synchronously; callers should invoke
// it in a goroutine for async operation.
func (m *Manager) Create(ctx context.Context, triggeredBy *string) (string, int64, error) {
	// Create job record.
	job, err := m.repo.Create(ctx, "create", triggeredBy)
	if err != nil {
		return "", 0, fmt.Errorf("create backup job: %w", err)
	}

	path, size, err := m.runCreate(ctx, job.ID)
	if err != nil {
		_ = m.repo.Fail(ctx, job.ID, err.Error())
		return "", 0, err
	}

	if err := m.repo.Complete(ctx, job.ID, path); err != nil {
		m.logger.Error("failed to mark backup job complete", "error", err)
	}

	return path, size, nil
}

// CreateAsync creates a backup asynchronously and returns the job ID immediately.
func (m *Manager) CreateAsync(ctx context.Context, triggeredBy *string) (string, error) {
	job, err := m.repo.Create(ctx, "create", triggeredBy)
	if err != nil {
		return "", fmt.Errorf("create backup job: %w", err)
	}

	go func() {
		bgCtx := context.Background()
		path, _, err := m.runCreate(bgCtx, job.ID)
		if err != nil {
			m.logger.Error("async backup failed", "job_id", job.ID, "error", err)
			_ = m.repo.Fail(bgCtx, job.ID, err.Error())
			return
		}
		if err := m.repo.Complete(bgCtx, job.ID, path); err != nil {
			m.logger.Error("failed to mark async backup complete", "job_id", job.ID, "error", err)
		}
	}()

	return job.ID, nil
}

func (m *Manager) runCreate(ctx context.Context, jobID string) (string, int64, error) {
	// Ensure backup directory exists.
	if err := os.MkdirAll(m.cfg.BackupDir, 0700); err != nil {
		return "", 0, fmt.Errorf("create backup directory: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102-150405")
	archiveName := fmt.Sprintf("vectis-%s.tar.gz", timestamp)
	archivePath := filepath.Join(m.cfg.BackupDir, archiveName)

	// Create a temp working directory for assembling the backup contents.
	tmpDir, err := os.MkdirTemp("", "vectis-backup-*")
	if err != nil {
		return "", 0, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Step 1: Database dump (0% -> 25%)
	_ = m.repo.UpdateProgress(ctx, jobID, 5, "Dumping database")
	m.logger.Info("backup: dumping database", "job_id", jobID)

	dbDumpPath := filepath.Join(tmpDir, "database.sql")
	if err := m.dumpDatabase(ctx, dbDumpPath); err != nil {
		return "", 0, fmt.Errorf("database dump: %w", err)
	}
	_ = m.repo.UpdateProgress(ctx, jobID, 25, "Database dump complete")

	// Step 2: Archive mail data (25% -> 60%)
	_ = m.repo.UpdateProgress(ctx, jobID, 30, "Archiving mail data")
	m.logger.Info("backup: archiving mail data", "job_id", jobID)

	mailArchive := filepath.Join(tmpDir, "mail-data.tar")
	if err := m.archiveDirectory(ctx, m.cfg.MailDataDir, mailArchive); err != nil {
		// Mail data dir might not exist yet (fresh install), treat as non-fatal.
		if !os.IsNotExist(err) {
			return "", 0, fmt.Errorf("archive mail data: %w", err)
		}
		m.logger.Warn("backup: mail data directory not found, skipping", "path", m.cfg.MailDataDir)
	}
	_ = m.repo.UpdateProgress(ctx, jobID, 60, "Mail data archived")

	// Step 3: Copy config files (60% -> 80%)
	_ = m.repo.UpdateProgress(ctx, jobID, 65, "Copying configuration")
	m.logger.Info("backup: copying config files", "job_id", jobID)

	configArchive := filepath.Join(tmpDir, "config.tar")
	if err := m.archiveDirectory(ctx, m.cfg.ConfigDir, configArchive); err != nil {
		if !os.IsNotExist(err) {
			return "", 0, fmt.Errorf("archive config: %w", err)
		}
		m.logger.Warn("backup: config directory not found, skipping", "path", m.cfg.ConfigDir)
	}
	_ = m.repo.UpdateProgress(ctx, jobID, 80, "Configuration copied")

	// Step 4: Copy DKIM keys (80% -> 90%)
	_ = m.repo.UpdateProgress(ctx, jobID, 85, "Copying DKIM keys")
	m.logger.Info("backup: copying DKIM keys", "job_id", jobID)

	dkimArchive := filepath.Join(tmpDir, "dkim.tar")
	if err := m.archiveDirectory(ctx, m.cfg.DKIMDir, dkimArchive); err != nil {
		if !os.IsNotExist(err) {
			return "", 0, fmt.Errorf("archive DKIM keys: %w", err)
		}
		m.logger.Warn("backup: DKIM directory not found, skipping", "path", m.cfg.DKIMDir)
	}
	_ = m.repo.UpdateProgress(ctx, jobID, 90, "DKIM keys copied")

	// Step 5: Create final tar.gz archive (90% -> 100%)
	_ = m.repo.UpdateProgress(ctx, jobID, 92, "Creating backup archive")
	m.logger.Info("backup: creating final archive", "job_id", jobID, "path", archivePath)

	if err := m.createFinalArchive(ctx, tmpDir, archivePath); err != nil {
		// Clean up partial archive.
		os.Remove(archivePath)
		return "", 0, fmt.Errorf("create archive: %w", err)
	}

	// Verify the archive.
	info, err := os.Stat(archivePath)
	if err != nil {
		return "", 0, fmt.Errorf("stat archive: %w", err)
	}
	if info.Size() == 0 {
		os.Remove(archivePath)
		return "", 0, fmt.Errorf("backup archive is empty")
	}

	m.logger.Info("backup complete",
		"job_id", jobID,
		"path", archivePath,
		"size_bytes", info.Size(),
	)

	return archivePath, info.Size(), nil
}

// Restore restores from a backup archive. This is a destructive operation:
// it stops services, restores database, mail data, config, and DKIM keys,
// then restarts services and runs a health check.
func (m *Manager) Restore(ctx context.Context, backupPath string, triggeredBy *string) error {
	// Validate the archive first.
	if err := m.validateArchive(ctx, backupPath); err != nil {
		return fmt.Errorf("invalid backup archive: %w", err)
	}

	job, err := m.repo.Create(ctx, "restore", triggeredBy)
	if err != nil {
		return fmt.Errorf("create restore job: %w", err)
	}

	err = m.runRestore(ctx, job.ID, backupPath)
	if err != nil {
		_ = m.repo.Fail(ctx, job.ID, err.Error())
		return err
	}

	if err := m.repo.Complete(ctx, job.ID, backupPath); err != nil {
		m.logger.Error("failed to mark restore job complete", "error", err)
	}

	return nil
}

// RestoreAsync triggers a restore asynchronously and returns the job ID.
func (m *Manager) RestoreAsync(ctx context.Context, backupPath string, triggeredBy *string) (string, error) {
	// Validate synchronously before starting async work.
	if err := m.validateArchive(ctx, backupPath); err != nil {
		return "", fmt.Errorf("invalid backup archive: %w", err)
	}

	job, err := m.repo.Create(ctx, "restore", triggeredBy)
	if err != nil {
		return "", fmt.Errorf("create restore job: %w", err)
	}

	go func() {
		bgCtx := context.Background()
		if err := m.runRestore(bgCtx, job.ID, backupPath); err != nil {
			m.logger.Error("async restore failed", "job_id", job.ID, "error", err)
			_ = m.repo.Fail(bgCtx, job.ID, err.Error())
			return
		}
		if err := m.repo.Complete(bgCtx, job.ID, backupPath); err != nil {
			m.logger.Error("failed to mark async restore complete", "job_id", job.ID, "error", err)
		}
	}()

	return job.ID, nil
}

func (m *Manager) runRestore(ctx context.Context, jobID, backupPath string) error {
	// Extract archive to temp dir.
	tmpDir, err := os.MkdirTemp("", "vectis-restore-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Step 1: Extract backup archive (0% -> 15%)
	_ = m.repo.UpdateProgress(ctx, jobID, 5, "Extracting backup archive")
	m.logger.Info("restore: extracting archive", "job_id", jobID, "path", backupPath)

	cmd := exec.CommandContext(ctx, "tar", "-xzf", backupPath, "-C", tmpDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("extract archive: %w: %s", err, string(output))
	}
	_ = m.repo.UpdateProgress(ctx, jobID, 15, "Archive extracted")

	// Step 2: Stop services (15% -> 25%)
	_ = m.repo.UpdateProgress(ctx, jobID, 18, "Stopping services")
	m.logger.Info("restore: stopping services", "job_id", jobID)

	if err := m.stopServices(ctx); err != nil {
		m.logger.Warn("restore: failed to stop services (may not be running)", "error", err)
	}
	_ = m.repo.UpdateProgress(ctx, jobID, 25, "Services stopped")

	// Step 3: Restore database (25% -> 50%)
	dbDump := filepath.Join(tmpDir, "database.sql")
	if _, err := os.Stat(dbDump); err == nil {
		_ = m.repo.UpdateProgress(ctx, jobID, 30, "Restoring database")
		m.logger.Info("restore: restoring database", "job_id", jobID)

		if err := m.restoreDatabase(ctx, dbDump); err != nil {
			return fmt.Errorf("restore database: %w", err)
		}
	} else {
		m.logger.Warn("restore: no database dump found in archive", "job_id", jobID)
	}
	_ = m.repo.UpdateProgress(ctx, jobID, 50, "Database restored")

	// Step 4: Restore mail data (50% -> 70%)
	mailArchive := filepath.Join(tmpDir, "mail-data.tar")
	if _, err := os.Stat(mailArchive); err == nil {
		_ = m.repo.UpdateProgress(ctx, jobID, 55, "Restoring mail data")
		m.logger.Info("restore: restoring mail data", "job_id", jobID)

		if err := m.restoreDirectory(ctx, mailArchive, m.cfg.MailDataDir); err != nil {
			return fmt.Errorf("restore mail data: %w", err)
		}
	} else {
		m.logger.Warn("restore: no mail data archive found", "job_id", jobID)
	}
	_ = m.repo.UpdateProgress(ctx, jobID, 70, "Mail data restored")

	// Step 5: Restore config files (70% -> 80%)
	configArchive := filepath.Join(tmpDir, "config.tar")
	if _, err := os.Stat(configArchive); err == nil {
		_ = m.repo.UpdateProgress(ctx, jobID, 75, "Restoring configuration")
		m.logger.Info("restore: restoring config", "job_id", jobID)

		if err := m.restoreDirectory(ctx, configArchive, m.cfg.ConfigDir); err != nil {
			return fmt.Errorf("restore config: %w", err)
		}
	} else {
		m.logger.Warn("restore: no config archive found", "job_id", jobID)
	}
	_ = m.repo.UpdateProgress(ctx, jobID, 80, "Configuration restored")

	// Step 6: Restore DKIM keys (80% -> 85%)
	dkimArchive := filepath.Join(tmpDir, "dkim.tar")
	if _, err := os.Stat(dkimArchive); err == nil {
		_ = m.repo.UpdateProgress(ctx, jobID, 82, "Restoring DKIM keys")
		m.logger.Info("restore: restoring DKIM keys", "job_id", jobID)

		if err := m.restoreDirectory(ctx, dkimArchive, m.cfg.DKIMDir); err != nil {
			return fmt.Errorf("restore DKIM keys: %w", err)
		}
	} else {
		m.logger.Warn("restore: no DKIM archive found", "job_id", jobID)
	}
	_ = m.repo.UpdateProgress(ctx, jobID, 85, "DKIM keys restored")

	// Step 7: Start services (85% -> 95%)
	_ = m.repo.UpdateProgress(ctx, jobID, 88, "Starting services")
	m.logger.Info("restore: starting services", "job_id", jobID)

	if err := m.startServices(ctx); err != nil {
		return fmt.Errorf("start services: %w", err)
	}
	_ = m.repo.UpdateProgress(ctx, jobID, 95, "Services started")

	// Step 8: Health check (95% -> 100%)
	_ = m.repo.UpdateProgress(ctx, jobID, 96, "Running health checks")
	m.logger.Info("restore: running health checks", "job_id", jobID)

	if err := m.healthCheck(ctx); err != nil {
		m.logger.Warn("restore: health check reported issues", "error", err)
		// Non-fatal: services may still be starting up.
	}

	m.logger.Info("restore complete", "job_id", jobID, "backup_path", backupPath)
	return nil
}

// List returns available backup archives on disk with metadata.
func (m *Manager) List() ([]BackupInfo, error) {
	entries, err := os.ReadDir(m.cfg.BackupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read backup directory: %w", err)
	}

	var backups []BackupInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".tar.gz") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			m.logger.Warn("failed to stat backup file", "name", entry.Name(), "error", err)
			continue
		}

		backups = append(backups, BackupInfo{
			Path:      filepath.Join(m.cfg.BackupDir, entry.Name()),
			Name:      entry.Name(),
			Size:      info.Size(),
			CreatedAt: info.ModTime(),
		})
	}

	// Sort newest first.
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].CreatedAt.After(backups[j].CreatedAt)
	})

	return backups, nil
}

// GetJobStatus returns the current status of a backup/restore job.
func (m *Manager) GetJobStatus(ctx context.Context, jobID string) (*repository.BackupJob, error) {
	return m.repo.GetByID(ctx, jobID)
}

// ListJobs returns recent backup jobs.
func (m *Manager) ListJobs(ctx context.Context, limit int) ([]repository.BackupJob, error) {
	return m.repo.List(ctx, limit)
}

// -----------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------

// dumpDatabase runs pg_dump and writes the output to dstPath.
func (m *Manager) dumpDatabase(ctx context.Context, dstPath string) error {
	args := []string{
		"--host", m.cfg.DBHost,
		"--port", fmt.Sprintf("%d", m.cfg.DBPort),
		"--username", m.cfg.DBUser,
		"--dbname", m.cfg.DBName,
		"--no-password",
		"--clean",
		"--if-exists",
		"--file", dstPath,
	}

	cmd := exec.CommandContext(ctx, "pg_dump", args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", m.cfg.DBPassword))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pg_dump failed: %w: %s", err, string(output))
	}

	// Verify the dump is non-empty.
	info, err := os.Stat(dstPath)
	if err != nil {
		return fmt.Errorf("stat database dump: %w", err)
	}
	if info.Size() == 0 {
		return fmt.Errorf("database dump is empty")
	}

	m.logger.Info("database dump complete", "path", dstPath, "size_bytes", info.Size())
	return nil
}

// restoreDatabase restores a database from a SQL dump using psql.
func (m *Manager) restoreDatabase(ctx context.Context, dumpPath string) error {
	args := []string{
		"--host", m.cfg.DBHost,
		"--port", fmt.Sprintf("%d", m.cfg.DBPort),
		"--username", m.cfg.DBUser,
		"--dbname", m.cfg.DBName,
		"--no-password",
		"--single-transaction",
		"--file", dumpPath,
	}

	cmd := exec.CommandContext(ctx, "psql", args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", m.cfg.DBPassword))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("psql restore failed: %w: %s", err, string(output))
	}

	m.logger.Info("database restored", "path", dumpPath)
	return nil
}

// archiveDirectory creates a tar of a directory. If the source directory
// does not exist, returns os.ErrNotExist.
func (m *Manager) archiveDirectory(ctx context.Context, srcDir, dstPath string) error {
	if _, err := os.Stat(srcDir); err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "tar",
		"-cf", dstPath,
		"-C", filepath.Dir(srcDir),
		filepath.Base(srcDir),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tar failed for %s: %w: %s", srcDir, err, string(output))
	}

	return nil
}

// restoreDirectory extracts a tar archive, then replaces the target directory
// with the extracted contents.
func (m *Manager) restoreDirectory(ctx context.Context, archivePath, targetDir string) error {
	// Ensure target parent exists.
	if err := os.MkdirAll(filepath.Dir(targetDir), 0755); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}

	// Remove existing target directory.
	if err := os.RemoveAll(targetDir); err != nil {
		return fmt.Errorf("remove existing directory %s: %w", targetDir, err)
	}

	// Extract tar to the parent directory (tar contains the base directory name).
	cmd := exec.CommandContext(ctx, "tar",
		"-xf", archivePath,
		"-C", filepath.Dir(targetDir),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tar extract failed for %s: %w: %s", archivePath, err, string(output))
	}

	return nil
}

// createFinalArchive creates a tar.gz of the assembled backup directory.
func (m *Manager) createFinalArchive(ctx context.Context, srcDir, dstPath string) error {
	cmd := exec.CommandContext(ctx, "tar",
		"-czf", dstPath,
		"-C", srcDir,
		".",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("create final archive: %w: %s", err, string(output))
	}

	return nil
}

// validateArchive checks that the archive is a valid tar.gz file.
func (m *Manager) validateArchive(ctx context.Context, archivePath string) error {
	if _, err := os.Stat(archivePath); err != nil {
		return fmt.Errorf("archive file not found: %w", err)
	}

	cmd := exec.CommandContext(ctx, "tar", "-tzf", archivePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("archive validation failed: %w: %s", err, string(output))
	}

	// Check that it contains expected files.
	contents := string(output)
	if !strings.Contains(contents, "database.sql") {
		m.logger.Warn("backup archive missing database.sql — partial backup")
	}

	return nil
}

// stopServices stops all Docker Compose services.
func (m *Manager) stopServices(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", m.cfg.ComposePath,
		"stop",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker compose stop: %w: %s", err, string(output))
	}
	return nil
}

// startServices starts all Docker Compose services.
func (m *Manager) startServices(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", m.cfg.ComposePath,
		"up", "-d",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker compose up: %w: %s", err, string(output))
	}
	return nil
}

// healthCheck runs docker compose ps to verify services are running.
func (m *Manager) healthCheck(ctx context.Context) error {
	// Give services a moment to start.
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", m.cfg.ComposePath,
		"ps", "--format", "json",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("health check failed: %w: %s", err, string(output))
	}

	m.logger.Info("health check output", "output", string(output))
	return nil
}

// copyFile copies a single file from src to dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
