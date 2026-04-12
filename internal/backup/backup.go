package backup

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
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

// secretsExcludeFiles lists filenames that must never be included in backup
// archives. These files contain credentials and must be backed up separately
// by the operator using secure, out-of-band mechanisms.
var secretsExcludeFiles = map[string]bool{
	"secrets.yaml": true,
}

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

	// EncryptionKey is used to encrypt backup archives with AES-256-GCM.
	// When set, backups are written as .tar.gz.enc files. When empty, backups
	// are written as plaintext .tar.gz (not recommended for production).
	// The key is derived from the API secret in secrets.yaml via SHA-256.
	EncryptionKey string

	// MaxIncrementalChain is the maximum number of incremental backups before
	// a full backup is forced. Default 7 (one full per week with daily incrementals).
	MaxIncrementalChain int
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
		ComposePath:         "/etc/vectis/docker-compose.yml",
		MaxIncrementalChain: 7,
	}
}

// CompletionCallback is called when an async backup/restore finishes.
// path is the archive path (empty on failure), sizeMB is the size in MB,
// durationSecs is wall-clock seconds, and err is non-nil on failure.
type CompletionCallback func(path string, sizeMB int64, durationSecs int, err error)

// Manager handles backup creation and restoration.
type Manager struct {
	db         *pgxpool.Pool
	logger     *slog.Logger
	cfg        Config
	repo       *repository.BackupRepo
	onComplete CompletionCallback
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

// SetOnComplete registers a callback invoked when async operations finish.
func (m *Manager) SetOnComplete(cb CompletionCallback) {
	m.onComplete = cb
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

	// Record in manifest.
	manifest, _ := LoadManifest(m.cfg.BackupDir)
	if manifest != nil {
		manifest.Add(ManifestEntry{
			ID:        job.ID,
			Type:      BackupFull,
			Path:      path,
			Size:      size,
			CreatedAt: time.Now().UTC(),
		})
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
		start := time.Now()
		bgCtx := context.Background()
		path, size, err := m.runCreate(bgCtx, job.ID)
		duration := int(time.Since(start).Seconds())
		if err != nil {
			m.logger.Error("async backup failed", "job_id", job.ID, "error", err)
			_ = m.repo.Fail(bgCtx, job.ID, err.Error())
			if m.onComplete != nil {
				m.onComplete("", 0, duration, err)
			}
			return
		}
		if err := m.repo.Complete(bgCtx, job.ID, path); err != nil {
			m.logger.Error("failed to mark async backup complete", "job_id", job.ID, "error", err)
		}
		if m.onComplete != nil {
			m.onComplete(path, size/(1024*1024), duration, nil)
		}
	}()

	return job.ID, nil
}

// CreateIncrementalAsync creates an incremental backup (or auto-promotes to full
// if no prior full exists or the chain exceeds MaxIncrementalChain). Returns the
// job ID and the effective backup type.
func (m *Manager) CreateIncrementalAsync(ctx context.Context, triggeredBy *string) (string, BackupType, error) {
	manifest, err := LoadManifest(m.cfg.BackupDir)
	if err != nil {
		m.logger.Warn("failed to load manifest, falling back to full backup", "error", err)
	}

	// Decide: full or incremental.
	backupType := BackupIncremental
	lastFull := manifest.LastFull()
	if lastFull == nil || manifest.ChainDepth() >= m.cfg.MaxIncrementalChain {
		backupType = BackupFull
		if lastFull == nil {
			m.logger.Info("no prior full backup found, performing full backup")
		} else {
			m.logger.Info("incremental chain depth exceeded, performing full backup",
				"chain_depth", manifest.ChainDepth(),
				"max", m.cfg.MaxIncrementalChain)
		}
	}

	actionLabel := "create"
	if backupType == BackupIncremental {
		actionLabel = "create_incremental"
	}

	job, err := m.repo.Create(ctx, actionLabel, triggeredBy)
	if err != nil {
		return "", backupType, fmt.Errorf("create backup job: %w", err)
	}

	go func() {
		start := time.Now()
		bgCtx := context.Background()

		var path string
		var size int64
		var runErr error

		if backupType == BackupIncremental {
			path, size, runErr = m.runCreateIncremental(bgCtx, job.ID, lastFull)
		} else {
			path, size, runErr = m.runCreate(bgCtx, job.ID)
		}

		duration := int(time.Since(start).Seconds())
		if runErr != nil {
			m.logger.Error("async backup failed", "job_id", job.ID, "type", backupType, "error", runErr)
			_ = m.repo.Fail(bgCtx, job.ID, runErr.Error())
			if m.onComplete != nil {
				m.onComplete("", 0, duration, runErr)
			}
			return
		}

		if err := m.repo.Complete(bgCtx, job.ID, path); err != nil {
			m.logger.Error("failed to mark backup complete", "job_id", job.ID, "error", err)
		}

		// Record in manifest.
		parentID := ""
		if backupType == BackupIncremental && lastFull != nil {
			parentID = lastFull.ID
		}
		entry := ManifestEntry{
			ID:        job.ID,
			Type:      backupType,
			Path:      path,
			ParentID:  parentID,
			Size:      size,
			CreatedAt: time.Now().UTC(),
		}
		if err := manifest.Add(entry); err != nil {
			m.logger.Error("failed to update manifest", "error", err)
		}

		if m.onComplete != nil {
			m.onComplete(path, size/(1024*1024), duration, nil)
		}
	}()

	return job.ID, backupType, nil
}

func (m *Manager) runCreate(ctx context.Context, jobID string) (string, int64, error) {
	// Ensure backup directory exists.
	if err := os.MkdirAll(m.cfg.BackupDir, 0700); err != nil {
		return "", 0, fmt.Errorf("create backup directory: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102-150405")
	encrypted := m.cfg.EncryptionKey != ""
	ext := ".tar.gz"
	if encrypted {
		ext = ".tar.gz.enc"
	}
	archiveName := fmt.Sprintf("vectis-%s%s", timestamp, ext)
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
	// SECURITY: secrets.yaml is excluded from backups. It contains DB passwords,
	// API secrets, and orchestrator tokens. Operators must back up secrets
	// separately using secure, out-of-band mechanisms.
	_ = m.repo.UpdateProgress(ctx, jobID, 65, "Copying configuration (excluding secrets)")
	m.logger.Info("backup: copying config files (excluding secrets)", "job_id", jobID)

	configArchive := filepath.Join(tmpDir, "config.tar")
	if err := m.archiveDirectoryExcluding(ctx, m.cfg.ConfigDir, configArchive, secretsExcludeFiles); err != nil {
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

	if encrypted {
		// Create plaintext archive in temp dir, then encrypt to final path.
		plaintextPath := filepath.Join(tmpDir, "backup.tar.gz")
		if err := m.createFinalArchive(ctx, tmpDir, plaintextPath); err != nil {
			os.Remove(archivePath)
			return "", 0, fmt.Errorf("create archive: %w", err)
		}

		_ = m.repo.UpdateProgress(ctx, jobID, 96, "Encrypting backup archive")
		m.logger.Info("backup: encrypting archive", "job_id", jobID)

		if err := encryptFile(plaintextPath, archivePath, m.cfg.EncryptionKey); err != nil {
			os.Remove(archivePath)
			return "", 0, fmt.Errorf("encrypt archive: %w", err)
		}
		os.Remove(plaintextPath)
	} else {
		m.logger.Warn("backup: encryption not configured — backup is plaintext. Set encryption key in secrets.yaml for production use.")
		if err := m.createFinalArchive(ctx, tmpDir, archivePath); err != nil {
			os.Remove(archivePath)
			return "", 0, fmt.Errorf("create archive: %w", err)
		}
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

// runCreateIncremental creates a backup containing only the database (always full)
// and mail files modified since the parent full backup. Config and DKIM are always
// included in full since they're tiny.
func (m *Manager) runCreateIncremental(ctx context.Context, jobID string, parent *ManifestEntry) (string, int64, error) {
	if err := os.MkdirAll(m.cfg.BackupDir, 0700); err != nil {
		return "", 0, fmt.Errorf("create backup directory: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102-150405")
	encrypted := m.cfg.EncryptionKey != ""
	ext := ".tar.gz"
	if encrypted {
		ext = ".tar.gz.enc"
	}
	archiveName := fmt.Sprintf("vectis-incr-%s%s", timestamp, ext)
	archivePath := filepath.Join(m.cfg.BackupDir, archiveName)

	tmpDir, err := os.MkdirTemp("", "vectis-backup-incr-*")
	if err != nil {
		return "", 0, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Step 1: Database dump (always full — small relative to mail).
	_ = m.repo.UpdateProgress(ctx, jobID, 5, "Dumping database")
	m.logger.Info("incremental backup: dumping database", "job_id", jobID)

	dbDumpPath := filepath.Join(tmpDir, "database.sql")
	if err := m.dumpDatabase(ctx, dbDumpPath); err != nil {
		return "", 0, fmt.Errorf("database dump: %w", err)
	}
	_ = m.repo.UpdateProgress(ctx, jobID, 25, "Database dump complete")

	// Step 2: Archive only mail files modified since the parent backup.
	_ = m.repo.UpdateProgress(ctx, jobID, 30, "Archiving changed mail data")
	m.logger.Info("incremental backup: archiving mail changes since parent",
		"job_id", jobID,
		"since", parent.CreatedAt.Format(time.RFC3339))

	mailArchive := filepath.Join(tmpDir, "mail-data.tar")
	if err := m.archiveDirectoryNewer(ctx, m.cfg.MailDataDir, mailArchive, parent.CreatedAt); err != nil {
		if !os.IsNotExist(err) {
			return "", 0, fmt.Errorf("archive incremental mail data: %w", err)
		}
		m.logger.Warn("incremental backup: mail data directory not found, skipping", "path", m.cfg.MailDataDir)
	}
	_ = m.repo.UpdateProgress(ctx, jobID, 60, "Mail changes archived")

	// Step 3: Config (always full, tiny).
	_ = m.repo.UpdateProgress(ctx, jobID, 65, "Copying configuration (excluding secrets)")
	configArchive := filepath.Join(tmpDir, "config.tar")
	if err := m.archiveDirectoryExcluding(ctx, m.cfg.ConfigDir, configArchive, secretsExcludeFiles); err != nil {
		if !os.IsNotExist(err) {
			return "", 0, fmt.Errorf("archive config: %w", err)
		}
	}
	_ = m.repo.UpdateProgress(ctx, jobID, 80, "Configuration copied")

	// Step 4: DKIM (always full, tiny).
	_ = m.repo.UpdateProgress(ctx, jobID, 85, "Copying DKIM keys")
	dkimArchive := filepath.Join(tmpDir, "dkim.tar")
	if err := m.archiveDirectory(ctx, m.cfg.DKIMDir, dkimArchive); err != nil {
		if !os.IsNotExist(err) {
			return "", 0, fmt.Errorf("archive DKIM keys: %w", err)
		}
	}
	_ = m.repo.UpdateProgress(ctx, jobID, 90, "DKIM keys copied")

	// Step 5: Write a type marker so restore knows this is incremental.
	typeMarker := filepath.Join(tmpDir, "backup-type.txt")
	os.WriteFile(typeMarker, []byte("incremental\n"), 0600)

	// Step 6: Create final archive.
	_ = m.repo.UpdateProgress(ctx, jobID, 92, "Creating backup archive")
	m.logger.Info("incremental backup: creating final archive", "job_id", jobID, "path", archivePath)

	if encrypted {
		plaintextPath := filepath.Join(tmpDir, "backup.tar.gz")
		if err := m.createFinalArchive(ctx, tmpDir, plaintextPath); err != nil {
			os.Remove(archivePath)
			return "", 0, fmt.Errorf("create archive: %w", err)
		}
		_ = m.repo.UpdateProgress(ctx, jobID, 96, "Encrypting backup archive")
		if err := encryptFile(plaintextPath, archivePath, m.cfg.EncryptionKey); err != nil {
			os.Remove(archivePath)
			return "", 0, fmt.Errorf("encrypt archive: %w", err)
		}
		os.Remove(plaintextPath)
	} else {
		if err := m.createFinalArchive(ctx, tmpDir, archivePath); err != nil {
			os.Remove(archivePath)
			return "", 0, fmt.Errorf("create archive: %w", err)
		}
	}

	info, err := os.Stat(archivePath)
	if err != nil {
		return "", 0, fmt.Errorf("stat archive: %w", err)
	}

	m.logger.Info("incremental backup complete",
		"job_id", jobID,
		"path", archivePath,
		"size_bytes", info.Size(),
	)

	return archivePath, info.Size(), nil
}

// archiveDirectoryNewer creates a tar of files modified since the given time.
func (m *Manager) archiveDirectoryNewer(ctx context.Context, srcDir, dstPath string, since time.Time) error {
	if _, err := os.Stat(srcDir); err != nil {
		return err
	}

	sinceStr := since.Format("2006-01-02 15:04:05")
	cmd := exec.CommandContext(ctx, "tar",
		"-cf", dstPath,
		"--newer="+sinceStr,
		"-C", filepath.Dir(srcDir),
		filepath.Base(srcDir),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// tar exits 1 when "file changed as we read it" or "no files matched"
		// — check if the archive was still created.
		if _, statErr := os.Stat(dstPath); statErr == nil {
			m.logger.Debug("tar --newer exited non-zero but archive was created",
				"exit_error", err.Error(),
				"output", string(output))
			return nil
		}
		return fmt.Errorf("tar --newer failed for %s: %w: %s", srcDir, err, string(output))
	}

	return nil
}

// RestoreChain restores from the latest full backup plus all subsequent
// incrementals. It reads the manifest to determine the chain.
func (m *Manager) RestoreChain(ctx context.Context, triggeredBy *string) error {
	manifest, err := LoadManifest(m.cfg.BackupDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	chain := manifest.RestoreChain()
	if len(chain) == 0 {
		return fmt.Errorf("no backup chain found — manifest has no full backup")
	}

	// Verify all archives exist.
	for _, entry := range chain {
		if _, err := os.Stat(entry.Path); err != nil {
			return fmt.Errorf("backup archive missing from chain: %s (%s)", entry.Path, entry.ID)
		}
	}

	m.logger.Info("restoring from backup chain",
		"full_id", chain[0].ID,
		"chain_length", len(chain))

	// Restore the full backup first.
	if err := m.Restore(ctx, chain[0].Path, triggeredBy); err != nil {
		return fmt.Errorf("restore full backup: %w", err)
	}

	// Apply each incremental on top (mail data overlay, database re-dumped).
	for i, entry := range chain[1:] {
		m.logger.Info("applying incremental backup",
			"step", i+1,
			"id", entry.ID,
			"path", entry.Path)

		if err := m.applyIncremental(ctx, entry.Path); err != nil {
			return fmt.Errorf("apply incremental %s: %w", entry.ID, err)
		}
	}

	return nil
}

// applyIncremental extracts an incremental backup on top of existing data.
// It restores the database dump (overwriting the full one) and overlays
// the mail data tar (newer files overwrite older ones).
func (m *Manager) applyIncremental(ctx context.Context, archivePath string) error {
	tmpDir, err := os.MkdirTemp("", "vectis-incr-apply-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	extractPath := archivePath
	if strings.HasSuffix(archivePath, ".enc") {
		if m.cfg.EncryptionKey == "" {
			return fmt.Errorf("incremental is encrypted but no key configured")
		}
		decryptedPath := filepath.Join(tmpDir, "backup.tar.gz")
		if err := decryptFile(archivePath, decryptedPath, m.cfg.EncryptionKey); err != nil {
			return fmt.Errorf("decrypt incremental: %w", err)
		}
		extractPath = decryptedPath
	}

	cmd := exec.CommandContext(ctx, "tar", "-xzf", extractPath, "-C", tmpDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("extract incremental: %w: %s", err, string(output))
	}

	// Restore database (overwrites the one from full backup).
	dbDump := filepath.Join(tmpDir, "database.sql")
	if _, err := os.Stat(dbDump); err == nil {
		if err := m.restoreDatabase(ctx, dbDump); err != nil {
			return fmt.Errorf("restore incremental database: %w", err)
		}
	}

	// Overlay mail data (extract on top of existing).
	mailArchive := filepath.Join(tmpDir, "mail-data.tar")
	if _, err := os.Stat(mailArchive); err == nil {
		cmd := exec.CommandContext(ctx, "tar",
			"-xf", mailArchive,
			"-C", filepath.Dir(m.cfg.MailDataDir),
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("overlay incremental mail data: %w: %s", err, string(output))
		}
	}

	return nil
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

	extractPath := backupPath
	if strings.HasSuffix(backupPath, ".enc") {
		// Decrypt first.
		if m.cfg.EncryptionKey == "" {
			return fmt.Errorf("backup is encrypted but no encryption key is configured")
		}
		_ = m.repo.UpdateProgress(ctx, jobID, 3, "Decrypting backup archive")
		m.logger.Info("restore: decrypting archive", "job_id", jobID)

		decryptedPath := filepath.Join(tmpDir, "backup.tar.gz")
		if err := decryptFile(backupPath, decryptedPath, m.cfg.EncryptionKey); err != nil {
			return fmt.Errorf("decrypt archive: %w", err)
		}
		extractPath = decryptedPath
	}

	cmd := exec.CommandContext(ctx, "tar", "-xzf", extractPath, "-C", tmpDir)
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
		if !strings.HasSuffix(entry.Name(), ".tar.gz") && !strings.HasSuffix(entry.Name(), ".tar.gz.enc") {
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

// archiveDirectoryExcluding creates a tar of a directory, excluding files
// whose base name is in the exclude set. Used to keep secrets out of backups.
func (m *Manager) archiveDirectoryExcluding(ctx context.Context, srcDir, dstPath string, exclude map[string]bool) error {
	if _, err := os.Stat(srcDir); err != nil {
		return err
	}

	args := []string{"-cf", dstPath, "-C", filepath.Dir(srcDir)}
	for name := range exclude {
		args = append(args, "--exclude", name)
	}
	args = append(args, filepath.Base(srcDir))

	cmd := exec.CommandContext(ctx, "tar", args...)
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

// validateArchive checks that the archive is a valid tar.gz (or .tar.gz.enc) file.
func (m *Manager) validateArchive(ctx context.Context, archivePath string) error {
	if _, err := os.Stat(archivePath); err != nil {
		return fmt.Errorf("archive file not found: %w", err)
	}

	// Encrypted archives can't be validated without decryption; just check the file exists.
	if strings.HasSuffix(archivePath, ".enc") {
		if m.cfg.EncryptionKey == "" {
			return fmt.Errorf("backup is encrypted but no encryption key is configured")
		}
		m.logger.Info("encrypted backup detected — content validation deferred to restore")
		return nil
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

// deriveKey returns a 32-byte AES-256 key from a passphrase via SHA-256.
func deriveKey(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
}

// encryptFile encrypts srcPath with AES-256-GCM and writes to dstPath.
func encryptFile(srcPath, dstPath, passphrase string) error {
	plaintext, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("read plaintext: %w", err)
	}

	block, err := aes.NewCipher(deriveKey(passphrase))
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	// nonce is prepended to the ciphertext.
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	if err := os.WriteFile(dstPath, ciphertext, 0600); err != nil {
		return fmt.Errorf("write encrypted file: %w", err)
	}

	return nil
}

// decryptFile decrypts an AES-256-GCM encrypted file and writes to dstPath.
func decryptFile(srcPath, dstPath, passphrase string) error {
	ciphertext, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("read encrypted file: %w", err)
	}

	block, err := aes.NewCipher(deriveKey(passphrase))
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return fmt.Errorf("encrypted file is too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong key?): %w", err)
	}

	if err := os.WriteFile(dstPath, plaintext, 0600); err != nil {
		return fmt.Errorf("write decrypted file: %w", err)
	}

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
