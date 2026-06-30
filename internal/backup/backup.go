package backup

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// secretsExcludeFiles lists tar exclude patterns for files that must never be
// included in backup archives. These files contain credentials and must be
// backed up separately by the operator using secure, out-of-band mechanisms.
//
// The pattern is a GLOB (`secrets.yaml*`), not just the literal name: config
// tooling leaves renamed copies in the config dir on every cutover
// (secrets.yaml.pre-v0.1.17, secrets.yaml.bak.YYYYMMDD, secrets.yaml.pre-f3.*,
// …) and each one holds the SAME live credentials. Excluding only the exact
// name `secrets.yaml` leaked those variants into the (encrypted) archive — found
// by the 2026-05-30 Scenario-B DR drill (Finding A). Patterns are passed
// verbatim to `tar --exclude` (no shell), so tar does the glob matching.
var secretsExcludeFiles = map[string]bool{
	"secrets.yaml*": true,
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

	// DBContainer / DBService / DBSuperuser / SuperuserPassword drive the
	// host-run restore path (runbook Scenario B). On the host the CLI cannot
	// resolve the Docker-internal "postgres" hostname, may not have psql
	// installed, and the app user (vectis_api) cannot restore superuser-owned
	// extension objects (e.g. pgcrypto). So restore loads the dump via
	// `docker exec <DBContainer> psql -U <DBSuperuser>` instead. Found by the
	// 2026-05-30 Scenario-B DR drill (Finding B).
	DBContainer       string // Postgres container name, default "vectis-postgres"
	DBService         string // Postgres docker-compose service name, default "postgres"
	DBSuperuser       string // DB superuser for restore, default "postgres"
	SuperuserPassword string // superuser password (secrets.database.superuser_password)

	// DirectDB forces the TCP pg_dump/psql path against cfg.DBHost even when the
	// Manager has a nil pool (host CLI). It is set by `vectis backup create
	// --db-host <host>` for operators whose Postgres is directly reachable from
	// the host, as an opt-in alternative to the default docker-exec-into-container
	// path (which the host CLI uses otherwise). A directly-reachable DB is assumed
	// already running, so the docker DB bring-up becomes a no-op.
	DirectDB bool

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
		BackupDir:           "/var/vectis/backups",
		MailDataDir:         "/var/vectis/mail",
		DKIMDir:             "/var/vectis/dkim",
		ConfigDir:           "/etc/vectis",
		SnapshotDir:         "/var/vectis/snapshots",
		DBHost:              "postgres",
		DBPort:              5432,
		DBName:              "vectis",
		DBUser:              "vectis_api",
		DBContainer:         "vectis-postgres",
		DBService:           "postgres",
		DBSuperuser:         "postgres",
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

	// Service-control hooks used by restore. They default to the docker
	// compose implementations below; the backup-restore integration test
	// overrides them with no-ops because CI has no compose stack to control.
	stopServicesFn  func(context.Context) error
	startServicesFn func(context.Context) error
	healthCheckFn   func(context.Context) error

	// dumpDBFn writes the database dump; restoreDBFn loads a SQL dump back into
	// Postgres; ensureDBUpFn makes sure the DB container is running before that
	// load. Defaults drive Docker (the production host path); the backup-restore
	// integration test overrides them because CI has no compose stack / DB
	// container to drive.
	dumpDBFn     func(ctx context.Context, dumpPath string) error
	restoreDBFn  func(ctx context.Context, dumpPath string) error
	ensureDBUpFn func(context.Context) error
}

// NewManager creates a new backup Manager.
func NewManager(db *pgxpool.Pool, logger *slog.Logger, cfg Config) *Manager {
	m := &Manager{
		db:     db,
		logger: logger,
		cfg:    cfg,
	}
	// A nil pool is valid: the host-run `vectis backup restore` cannot reach the
	// Docker-internal DB, so it runs without DB-backed job tracking. Guard repo
	// access via the job* helpers below.
	if db != nil {
		m.repo = repository.NewBackupRepo(db)
	}
	m.stopServicesFn = m.stopServices
	m.startServicesFn = m.startServices
	m.healthCheckFn = m.healthCheck
	if db != nil || cfg.DirectDB {
		// Reachable-DB path: either a real pool (in-app/api container, reachable
		// over the Docker network as cfg.DBUser) or an operator-supplied --db-host
		// (cfg.DirectDB) for a host that can reach Postgres directly. Use the TCP
		// pg_dump/psql path and skip the docker DB bring-up (the DB is assumed
		// already running). Only the default host CLI path (nil pool, no --db-host)
		// needs the docker-exec path + ensureDBUp.
		m.dumpDBFn = m.dumpDatabase
		m.restoreDBFn = m.restoreDatabase
		m.ensureDBUpFn = func(context.Context) error { return nil }
	} else {
		m.dumpDBFn = m.dumpDatabaseViaDocker
		m.restoreDBFn = m.restoreDatabaseViaDocker
		m.ensureDBUpFn = m.ensureDBUp
	}
	return m
}

// --- nil-safe job tracking ---------------------------------------------------
// These wrap the backup_jobs repo so the restore path works with a nil pool
// (host CLI restore: the DB is unreachable from the host until it is itself
// restored). When repo is nil, job tracking is skipped.

func (m *Manager) jobCreate(ctx context.Context, action string, triggeredBy *string) (string, error) {
	if m.repo == nil {
		return "no-db-" + action, nil
	}
	job, err := m.repo.Create(ctx, action, triggeredBy)
	if err != nil {
		return "", err
	}
	return job.ID, nil
}

func (m *Manager) jobProgress(ctx context.Context, jobID string, progress int, step string) {
	if m.repo == nil {
		return
	}
	_ = m.repo.UpdateProgress(ctx, jobID, progress, step)
}

func (m *Manager) jobFail(ctx context.Context, jobID, errMsg string) {
	if m.repo == nil {
		return
	}
	_ = m.repo.Fail(ctx, jobID, errMsg)
}

func (m *Manager) jobComplete(ctx context.Context, jobID, path string) error {
	if m.repo == nil {
		return nil
	}
	return m.repo.Complete(ctx, jobID, path)
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
	// Create job record. jobCreate is nil-pool-safe: the host CLI `vectis backup
	// create` runs without a DB pool (the host cannot resolve the Docker-internal
	// postgres hostname), so it skips DB job tracking — the same model the restore
	// path uses (Finding B follow-up, 2026-05-30 Scenario-B DR drill).
	jobID, err := m.jobCreate(ctx, "create", triggeredBy)
	if err != nil {
		return "", 0, fmt.Errorf("create backup job: %w", err)
	}

	path, size, err := m.runCreate(ctx, jobID)
	if err != nil {
		m.jobFail(ctx, jobID, err.Error())
		return "", 0, err
	}

	if err := m.jobComplete(ctx, jobID, path); err != nil {
		m.logger.Error("failed to mark backup job complete", "error", err)
	}

	// Record in manifest. The manifest ID must be UNIQUE per backup — it keys the
	// full→incremental chain in LastFull/IncrementalsSince/RestoreChain/Prune. On
	// the host CLI path there is no DB job row, so jobID is the non-unique sentinel
	// "no-db-create"; using it would make every host backup collide in the chain
	// (Copilot review, PR #3). Fall back to the archive's timestamped basename,
	// which is as unique as the archives themselves.
	manifest, _ := LoadManifest(m.cfg.BackupDir)
	if manifest != nil {
		manifestID := jobID
		if m.repo == nil {
			manifestID = filepath.Base(path)
		}
		manifest.Add(ManifestEntry{
			ID:        manifestID,
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
	m.jobProgress(ctx, jobID, 5, "Dumping database")
	m.logger.Info("backup: dumping database", "job_id", jobID)

	dbDumpPath := filepath.Join(tmpDir, "database.sql")
	if err := m.dumpDBFn(ctx, dbDumpPath); err != nil {
		return "", 0, fmt.Errorf("database dump: %w", err)
	}
	m.jobProgress(ctx, jobID, 25, "Database dump complete")

	// Step 2: Archive mail data (25% -> 60%)
	m.jobProgress(ctx, jobID, 30, "Archiving mail data")
	m.logger.Info("backup: archiving mail data", "job_id", jobID)

	mailArchive := filepath.Join(tmpDir, "mail-data.tar")
	if err := m.archiveDirectory(ctx, m.cfg.MailDataDir, mailArchive); err != nil {
		// Mail data dir might not exist yet (fresh install), treat as non-fatal.
		if !os.IsNotExist(err) {
			return "", 0, fmt.Errorf("archive mail data: %w", err)
		}
		m.logger.Warn("backup: mail data directory not found, skipping", "path", m.cfg.MailDataDir)
	}
	m.jobProgress(ctx, jobID, 60, "Mail data archived")

	// Step 3: Copy config files (60% -> 80%)
	// SECURITY: secrets.yaml is excluded from backups. It contains DB passwords,
	// API secrets, and orchestrator tokens. Operators must back up secrets
	// separately using secure, out-of-band mechanisms.
	m.jobProgress(ctx, jobID, 65, "Copying configuration (excluding secrets)")
	m.logger.Info("backup: copying config files (excluding secrets)", "job_id", jobID)

	configArchive := filepath.Join(tmpDir, "config.tar")
	if err := m.archiveDirectoryExcluding(ctx, m.cfg.ConfigDir, configArchive, secretsExcludeFiles); err != nil {
		if !os.IsNotExist(err) {
			return "", 0, fmt.Errorf("archive config: %w", err)
		}
		m.logger.Warn("backup: config directory not found, skipping", "path", m.cfg.ConfigDir)
	}
	m.jobProgress(ctx, jobID, 80, "Configuration copied")

	// Step 4: Copy DKIM keys (80% -> 90%)
	m.jobProgress(ctx, jobID, 85, "Copying DKIM keys")
	m.logger.Info("backup: copying DKIM keys", "job_id", jobID)

	dkimArchive := filepath.Join(tmpDir, "dkim.tar")
	if err := m.archiveDirectory(ctx, m.cfg.DKIMDir, dkimArchive); err != nil {
		if !os.IsNotExist(err) {
			return "", 0, fmt.Errorf("archive DKIM keys: %w", err)
		}
		m.logger.Warn("backup: DKIM directory not found, skipping", "path", m.cfg.DKIMDir)
	}
	m.jobProgress(ctx, jobID, 90, "DKIM keys copied")

	// Step 5: Create final tar.gz archive (90% -> 100%)
	m.jobProgress(ctx, jobID, 92, "Creating backup archive")
	m.logger.Info("backup: creating final archive", "job_id", jobID, "path", archivePath)

	if encrypted {
		// Create plaintext archive in temp dir, then encrypt to final path.
		plaintextPath := filepath.Join(tmpDir, "backup.tar.gz")
		if err := m.createFinalArchive(ctx, tmpDir, plaintextPath); err != nil {
			os.Remove(archivePath)
			return "", 0, fmt.Errorf("create archive: %w", err)
		}

		m.jobProgress(ctx, jobID, 96, "Encrypting backup archive")
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
	m.jobProgress(ctx, jobID, 5, "Dumping database")
	m.logger.Info("incremental backup: dumping database", "job_id", jobID)

	dbDumpPath := filepath.Join(tmpDir, "database.sql")
	if err := m.dumpDBFn(ctx, dbDumpPath); err != nil {
		return "", 0, fmt.Errorf("database dump: %w", err)
	}
	m.jobProgress(ctx, jobID, 25, "Database dump complete")

	// Step 2: Archive only mail files modified since the parent backup.
	m.jobProgress(ctx, jobID, 30, "Archiving changed mail data")
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
	m.jobProgress(ctx, jobID, 60, "Mail changes archived")

	// Step 3: Config (always full, tiny).
	m.jobProgress(ctx, jobID, 65, "Copying configuration (excluding secrets)")
	configArchive := filepath.Join(tmpDir, "config.tar")
	if err := m.archiveDirectoryExcluding(ctx, m.cfg.ConfigDir, configArchive, secretsExcludeFiles); err != nil {
		if !os.IsNotExist(err) {
			return "", 0, fmt.Errorf("archive config: %w", err)
		}
	}
	m.jobProgress(ctx, jobID, 80, "Configuration copied")

	// Step 4: DKIM (always full, tiny).
	m.jobProgress(ctx, jobID, 85, "Copying DKIM keys")
	dkimArchive := filepath.Join(tmpDir, "dkim.tar")
	if err := m.archiveDirectory(ctx, m.cfg.DKIMDir, dkimArchive); err != nil {
		if !os.IsNotExist(err) {
			return "", 0, fmt.Errorf("archive DKIM keys: %w", err)
		}
	}
	m.jobProgress(ctx, jobID, 90, "DKIM keys copied")

	// Step 5: Write a type marker so restore knows this is incremental.
	typeMarker := filepath.Join(tmpDir, "backup-type.txt")
	os.WriteFile(typeMarker, []byte("incremental\n"), 0600)

	// Step 6: Create final archive.
	m.jobProgress(ctx, jobID, 92, "Creating backup archive")
	m.logger.Info("incremental backup: creating final archive", "job_id", jobID, "path", archivePath)

	if encrypted {
		plaintextPath := filepath.Join(tmpDir, "backup.tar.gz")
		if err := m.createFinalArchive(ctx, tmpDir, plaintextPath); err != nil {
			os.Remove(archivePath)
			return "", 0, fmt.Errorf("create archive: %w", err)
		}
		m.jobProgress(ctx, jobID, 96, "Encrypting backup archive")
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

	// Restore database (overwrites the one from full backup). Uses the same
	// injectable hook as the full restore so the host path goes via docker exec.
	dbDump := filepath.Join(tmpDir, "database.sql")
	if _, err := os.Stat(dbDump); err == nil {
		if err := m.restoreDBFn(ctx, dbDump); err != nil {
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

	jobID, err := m.jobCreate(ctx, "restore", triggeredBy)
	if err != nil {
		return fmt.Errorf("create restore job: %w", err)
	}

	if err := m.runRestore(ctx, jobID, backupPath); err != nil {
		m.jobFail(ctx, jobID, err.Error())
		return err
	}

	if err := m.jobComplete(ctx, jobID, backupPath); err != nil {
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

	jobID, err := m.jobCreate(ctx, "restore", triggeredBy)
	if err != nil {
		return "", fmt.Errorf("create restore job: %w", err)
	}

	go func() {
		bgCtx := context.Background()
		if err := m.runRestore(bgCtx, jobID, backupPath); err != nil {
			m.logger.Error("async restore failed", "job_id", jobID, "error", err)
			m.jobFail(bgCtx, jobID, err.Error())
			return
		}
		if err := m.jobComplete(bgCtx, jobID, backupPath); err != nil {
			m.logger.Error("failed to mark async restore complete", "job_id", jobID, "error", err)
		}
	}()

	return jobID, nil
}

func (m *Manager) runRestore(ctx context.Context, jobID, backupPath string) error {
	// Extract archive to temp dir.
	tmpDir, err := os.MkdirTemp("", "vectis-restore-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Step 1: Extract backup archive (0% -> 15%)
	m.jobProgress(ctx, jobID, 5, "Extracting backup archive")
	m.logger.Info("restore: extracting archive", "job_id", jobID, "path", backupPath)

	extractPath := backupPath
	if strings.HasSuffix(backupPath, ".enc") {
		// Decrypt first.
		if m.cfg.EncryptionKey == "" {
			return fmt.Errorf("backup is encrypted but no encryption key is configured")
		}
		m.jobProgress(ctx, jobID, 3, "Decrypting backup archive")
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
	m.jobProgress(ctx, jobID, 15, "Archive extracted")

	// Step 2: Stop services (15% -> 25%)
	m.jobProgress(ctx, jobID, 18, "Stopping services")
	m.logger.Info("restore: stopping services", "job_id", jobID)

	if err := m.stopServicesFn(ctx); err != nil {
		m.logger.Warn("restore: failed to stop services (may not be running)", "error", err)
	}
	m.jobProgress(ctx, jobID, 25, "Services stopped")

	// Step 3: Restore database (25% -> 50%)
	dbDump := filepath.Join(tmpDir, "database.sql")
	if _, err := os.Stat(dbDump); err == nil {
		// The stop above took everything down, but the DB load targets a LIVE
		// Postgres (the host path drives it via `docker exec`, which needs a
		// running container). Bring the DB back up before loading.
		if err := m.ensureDBUpFn(ctx); err != nil {
			return fmt.Errorf("ensure database up before restore: %w", err)
		}
		m.jobProgress(ctx, jobID, 30, "Restoring database")
		m.logger.Info("restore: restoring database", "job_id", jobID)

		if err := m.restoreDBFn(ctx, dbDump); err != nil {
			return fmt.Errorf("restore database: %w", err)
		}
	} else {
		m.logger.Warn("restore: no database dump found in archive", "job_id", jobID)
	}
	m.jobProgress(ctx, jobID, 50, "Database restored")

	// Step 4: Restore mail data (50% -> 70%)
	mailArchive := filepath.Join(tmpDir, "mail-data.tar")
	if _, err := os.Stat(mailArchive); err == nil {
		m.jobProgress(ctx, jobID, 55, "Restoring mail data")
		m.logger.Info("restore: restoring mail data", "job_id", jobID)

		if err := m.restoreDirectory(ctx, mailArchive, m.cfg.MailDataDir); err != nil {
			return fmt.Errorf("restore mail data: %w", err)
		}
	} else {
		m.logger.Warn("restore: no mail data archive found", "job_id", jobID)
	}
	m.jobProgress(ctx, jobID, 70, "Mail data restored")

	// Step 5: Restore config files (70% -> 80%)
	configArchive := filepath.Join(tmpDir, "config.tar")
	if _, err := os.Stat(configArchive); err == nil {
		m.jobProgress(ctx, jobID, 75, "Restoring configuration")
		m.logger.Info("restore: restoring config", "job_id", jobID)

		// Preserve secrets.yaml*: it is never in a backup (excluded for
		// security) and must survive the config-dir replace (Finding E).
		if err := m.restoreDirectory(ctx, configArchive, m.cfg.ConfigDir, "secrets.yaml*"); err != nil {
			return fmt.Errorf("restore config: %w", err)
		}
	} else {
		m.logger.Warn("restore: no config archive found", "job_id", jobID)
	}
	m.jobProgress(ctx, jobID, 80, "Configuration restored")

	// Step 6: Restore DKIM keys (80% -> 85%)
	dkimArchive := filepath.Join(tmpDir, "dkim.tar")
	if _, err := os.Stat(dkimArchive); err == nil {
		m.jobProgress(ctx, jobID, 82, "Restoring DKIM keys")
		m.logger.Info("restore: restoring DKIM keys", "job_id", jobID)

		if err := m.restoreDirectory(ctx, dkimArchive, m.cfg.DKIMDir); err != nil {
			return fmt.Errorf("restore DKIM keys: %w", err)
		}
	} else {
		m.logger.Warn("restore: no DKIM archive found", "job_id", jobID)
	}
	m.jobProgress(ctx, jobID, 85, "DKIM keys restored")

	// Step 7: Start services (85% -> 95%)
	m.jobProgress(ctx, jobID, 88, "Starting services")
	m.logger.Info("restore: starting services", "job_id", jobID)

	if err := m.startServicesFn(ctx); err != nil {
		return fmt.Errorf("start services: %w", err)
	}
	m.jobProgress(ctx, jobID, 95, "Services started")

	// Step 8: Health check (95% -> 100%)
	m.jobProgress(ctx, jobID, 96, "Running health checks")
	m.logger.Info("restore: running health checks", "job_id", jobID)

	if err := m.healthCheckFn(ctx); err != nil {
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

// dumpDatabaseViaDocker writes a pg_dump of the database to dstPath by running
// pg_dump inside the Postgres container as the superuser via `docker exec`. It is
// the host CLI backup path (the create-side twin of restoreDatabaseViaDocker):
// the host running `vectis backup create` cannot resolve the Docker-internal
// "postgres" hostname and may not have pg_dump installed, so it dumps in-container
// over the local socket as the superuser instead. (Finding B follow-up, 2026-05-30
// Scenario-B DR drill.) The integration test overrides dumpDBFn with the
// TCP-based dumpDatabase because CI has no DB container to exec into.
func (m *Manager) dumpDatabaseViaDocker(ctx context.Context, dstPath string) error {
	out, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("create database dump file: %w", err)
	}
	defer out.Close()

	args := []string{"exec"}
	if m.cfg.SuperuserPassword != "" {
		// Pass the env NAME only in argv and supply the value via the docker
		// client's own environment, so the password never appears in `ps`/process
		// listings (matches restoreDatabaseViaDocker).
		args = append(args, "-e", "PGPASSWORD")
	}
	args = append(args,
		m.cfg.DBContainer,
		"pg_dump",
		"-U", m.cfg.DBSuperuser,
		"-d", m.cfg.DBName,
		"--no-password",
		"--clean",
		"--if-exists",
	)

	cmd := exec.CommandContext(ctx, "docker", args...)
	if m.cfg.SuperuserPassword != "" {
		cmd.Env = append(os.Environ(), "PGPASSWORD="+m.cfg.SuperuserPassword)
	}
	var stderr strings.Builder
	cmd.Stdout = out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker exec pg_dump failed: %w: %s", err, stderr.String())
	}

	info, err := os.Stat(dstPath)
	if err != nil {
		return fmt.Errorf("stat database dump: %w", err)
	}
	if info.Size() == 0 {
		return fmt.Errorf("database dump is empty")
	}

	m.logger.Info("database dump complete via docker exec",
		"container", m.cfg.DBContainer, "path", dstPath, "size_bytes", info.Size())
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

// restoreDatabaseViaDocker loads a SQL dump into the Postgres container as the
// superuser via `docker exec`. This is the production (host) restore path: the
// host running `vectis backup restore` cannot resolve the Docker-internal
// "postgres" hostname, may not have psql installed, and the app user cannot
// restore superuser-owned extension objects (pgcrypto fails with
// "must be owner of extension"). Executing psql inside the container as the
// superuser over the local socket sidesteps all three. (Finding B, 2026-05-30
// Scenario-B DR drill.) The integration test overrides restoreDBFn with the
// TCP-based restoreDatabase because CI has no DB container to exec into.
func (m *Manager) restoreDatabaseViaDocker(ctx context.Context, dumpPath string) error {
	f, err := os.Open(dumpPath)
	if err != nil {
		return fmt.Errorf("open database dump: %w", err)
	}
	defer f.Close()

	args := []string{"exec", "-i"}
	if m.cfg.SuperuserPassword != "" {
		// Belt-and-suspenders: the local socket connection is usually trust/peer
		// (no password), but pass it in case pg_hba requires it. Pass the env
		// NAME only in argv and supply the value via the docker client's own
		// environment, so the password never appears in `ps`/process listings.
		args = append(args, "-e", "PGPASSWORD")
	}
	args = append(args,
		m.cfg.DBContainer,
		"psql",
		"-U", m.cfg.DBSuperuser,
		"-d", m.cfg.DBName,
		"-v", "ON_ERROR_STOP=1",
		"--single-transaction",
	)

	cmd := exec.CommandContext(ctx, "docker", args...)
	if m.cfg.SuperuserPassword != "" {
		cmd.Env = append(os.Environ(), "PGPASSWORD="+m.cfg.SuperuserPassword)
	}
	cmd.Stdin = f
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker exec psql restore failed: %w: %s", err, string(output))
	}

	m.logger.Info("database restored via docker exec", "container", m.cfg.DBContainer, "path", dumpPath)
	return nil
}

// ensureDBUp brings the Postgres service up (idempotent) and waits for it to
// accept connections, so the docker-exec DB restore has a live target after the
// preceding stop took everything down.
func (m *Manager) ensureDBUp(ctx context.Context) error {
	up := exec.CommandContext(ctx, "docker", "compose",
		"-f", m.cfg.ComposePath,
		"up", "-d", m.cfg.DBService,
	)
	if output, err := up.CombinedOutput(); err != nil {
		return fmt.Errorf("docker compose up -d %s: %w: %s", m.cfg.DBService, err, string(output))
	}

	// Wait (bounded) for Postgres to be ready for connections.
	for i := 0; i < 30; i++ {
		check := exec.CommandContext(ctx, "docker", "exec",
			m.cfg.DBContainer, "pg_isready", "-U", m.cfg.DBSuperuser,
		)
		if err := check.Run(); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("postgres (%s) did not become ready after restart", m.cfg.DBContainer)
}

// archiveDirectory creates a tar of a directory. If the source directory
// does not exist, returns os.ErrNotExist. It is archiveDirectoryExcluding
// with an empty exclude set.
func (m *Manager) archiveDirectory(ctx context.Context, srcDir, dstPath string) error {
	return m.archiveDirectoryExcluding(ctx, srcDir, dstPath, nil)
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
func (m *Manager) restoreDirectory(ctx context.Context, archivePath, targetDir string, preserveGlobs ...string) error {
	// Ensure target parent exists.
	if err := os.MkdirAll(filepath.Dir(targetDir), 0755); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}

	// Stash files that must survive the restore before wiping the target. The
	// config restore passes "secrets.yaml*": secrets are NEVER in a backup
	// (excluded for security), so without this the RemoveAll below would delete
	// /etc/vectis/secrets.yaml and leave the install unbootable — a DR-breaking
	// bug found by the 2026-05-30 Scenario-B drill (Finding E).
	stash, err := os.MkdirTemp("", "vectis-restore-keep-*")
	if err != nil {
		return fmt.Errorf("create preserve stash: %w", err)
	}
	defer os.RemoveAll(stash)
	var preserved []string
	for _, glob := range preserveGlobs {
		matches, _ := filepath.Glob(filepath.Join(targetDir, glob))
		for _, src := range matches {
			// Only regular files are stashed. If a glob ever matched a directory
			// (or symlink/socket), copyFilePreserve's ReadFile would fail and
			// abort the entire restore — DR code must not abort on an edge like
			// that. In practice secrets.yaml* are always regular files.
			fi, statErr := os.Stat(src)
			if statErr != nil {
				return fmt.Errorf("stat preserved file %s: %w", src, statErr)
			}
			if !fi.Mode().IsRegular() {
				if m.logger != nil {
					m.logger.Warn("restore: skipping non-regular preserved match", "path", src, "mode", fi.Mode().String())
				}
				continue
			}
			base := filepath.Base(src)
			if err := copyFilePreserve(src, filepath.Join(stash, base)); err != nil {
				return fmt.Errorf("stash preserved file %s: %w", src, err)
			}
			preserved = append(preserved, base)
		}
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

	// Put the preserved files back (the extract recreated targetDir).
	if len(preserved) > 0 {
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			return fmt.Errorf("recreate target dir: %w", err)
		}
		for _, base := range preserved {
			if err := copyFilePreserve(filepath.Join(stash, base), filepath.Join(targetDir, base)); err != nil {
				return fmt.Errorf("restore preserved file %s: %w", base, err)
			}
		}
	}

	return nil
}

// copyFilePreserve copies src to dst preserving its permission bits. Used to
// stash and restore files (e.g. secrets.yaml) across a directory restore.
// (Only the permission bits are carried, not setuid/setgid/sticky — adequate
// for the 0600 secrets file this is used on.)
func copyFilePreserve(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, info.Mode().Perm())
}

// createFinalArchive creates a tar.gz of the assembled backup directory.
func (m *Manager) createFinalArchive(ctx context.Context, srcDir, dstPath string) error {
	// Guard against self-referential tar: if dstPath sits inside srcDir (the
	// encrypted flow's staging pattern — tmpDir/backup.tar.gz with srcDir=tmpDir),
	// tar races with itself because the output file grows while the parent
	// directory is being walked, triggering "file changed as we read it" → exit 1.
	// Write to a sibling temp path outside srcDir, then rename into place.
	absSrc, _ := filepath.Abs(srcDir)
	absDst, _ := filepath.Abs(dstPath)
	writePath := dstPath
	if strings.HasPrefix(absDst, absSrc+string(filepath.Separator)) {
		writePath = filepath.Join(filepath.Dir(absSrc), "._tmp-"+filepath.Base(dstPath))
	}

	cmd := exec.CommandContext(ctx, "tar",
		"-czf", writePath,
		"-C", srcDir,
		".",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		os.Remove(writePath)
		return fmt.Errorf("create final archive: %w: %s", err, string(output))
	}

	if writePath != dstPath {
		if err := os.Rename(writePath, dstPath); err != nil {
			os.Remove(writePath)
			return fmt.Errorf("move archive into place: %w", err)
		}
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

const (
	// backupMagicV1 prefixes archives whose key was derived with the salted,
	// memory-hard Argon2id KDF (#177). Its absence marks a legacy archive whose
	// key was a bare SHA-256 of the passphrase; decryptFile still reads those so
	// backups taken before the format change remain restorable.
	backupMagicV1 = "VXB1"
	backupSaltLen = 16
	// Argon2id parameters for backup key derivation. Backups are encrypted and
	// decrypted rarely (not on a hot path), so the KDF runs once per archive —
	// a 64 MB / t=3 / p=4 cost is comfortably affordable and makes offline brute
	// force of a weak passphrase expensive.
	backupArgonTime    = 3
	backupArgonMemory  = 64 * 1024 // 64 MB
	backupArgonThreads = 4
	backupKeyLen       = 32 // AES-256
)

// deriveKeyArgon2 stretches a passphrase into a 32-byte AES-256 key using
// Argon2id with a per-archive random salt (#177). The salt defeats
// precomputation/rainbow tables and ensures two archives never share a key even
// under the same passphrase; the memory-hard KDF makes brute force costly.
func deriveKeyArgon2(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, backupArgonTime, backupArgonMemory, backupArgonThreads, backupKeyLen)
}

// deriveKeyLegacy is the pre-#177 derivation: a bare, unsalted SHA-256 of the
// passphrase. Retained ONLY to decrypt archives written before the format
// change; never used to encrypt new archives.
func deriveKeyLegacy(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
}

// encryptFile encrypts srcPath with AES-256-GCM and writes to dstPath. The
// output layout is: magic || salt || nonce || ciphertext. A tampered salt or
// nonce derives the wrong key (or fails the GCM tag), so neither needs separate
// authentication.
func encryptFile(srcPath, dstPath, passphrase string) error {
	plaintext, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("read plaintext: %w", err)
	}

	salt := make([]byte, backupSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	block, err := aes.NewCipher(deriveKeyArgon2(passphrase, salt))
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

	// header = magic || salt || nonce; Seal appends the ciphertext to it.
	header := append([]byte(backupMagicV1), salt...)
	header = append(header, nonce...)
	out := gcm.Seal(header, nonce, plaintext, nil)

	if err := os.WriteFile(dstPath, out, 0600); err != nil {
		return fmt.Errorf("write encrypted file: %w", err)
	}

	return nil
}

// decryptFile decrypts an AES-256-GCM archive and writes to dstPath. It detects
// the format by the leading magic: a VXB1 archive carries a salt and is keyed
// with Argon2id; anything else is treated as a legacy (unsalted SHA-256) archive
// so pre-#177 backups still restore.
func decryptFile(srcPath, dstPath, passphrase string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("read encrypted file: %w", err)
	}

	var key, body []byte
	if len(data) >= len(backupMagicV1) && string(data[:len(backupMagicV1)]) == backupMagicV1 {
		rest := data[len(backupMagicV1):]
		if len(rest) < backupSaltLen {
			return fmt.Errorf("encrypted file is too short")
		}
		key = deriveKeyArgon2(passphrase, rest[:backupSaltLen])
		body = rest[backupSaltLen:]
	} else {
		// Legacy archive: nonce || ciphertext, keyed by bare SHA-256.
		key = deriveKeyLegacy(passphrase)
		body = data
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(body) < nonceSize {
		return fmt.Errorf("encrypted file is too short")
	}

	nonce, ciphertext := body[:nonceSize], body[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong key?): %w", err)
	}

	if err := os.WriteFile(dstPath, plaintext, 0600); err != nil {
		return fmt.Errorf("write decrypted file: %w", err)
	}

	return nil
}
