package database

import (
	"embed"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations
var migrationsFS embed.FS

// RunMigrations applies all pending up migrations.
func RunMigrations(dsn string, logger *slog.Logger) error {
	m, err := newMigrate(dsn)
	if err != nil {
		return err
	}
	defer m.Close()

	version, dirty, _ := m.Version()
	logger.Info("current migration state", "version", version, "dirty", dirty)

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("apply migrations: %w", err)
	}

	newVersion, _, _ := m.Version()
	if newVersion != version {
		logger.Info("migrations applied", "from_version", version, "to_version", newVersion)
	} else {
		logger.Info("no pending migrations")
	}

	return nil
}

// MigrationStatus returns the current migration version and dirty flag.
func MigrationStatus(dsn string) (version uint, dirty bool, err error) {
	m, err := newMigrate(dsn)
	if err != nil {
		return 0, false, err
	}
	defer m.Close()

	version, dirty, err = m.Version()
	if err == migrate.ErrNoChange {
		return version, dirty, nil
	}
	return version, dirty, err
}

// LatestMigrationVersion returns the highest migration version number available
// in the embedded migration files by scanning filenames.
func LatestMigrationVersion() uint {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return 0
	}
	var max uint
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// Migration filenames: 000001_name.up.sql
		name := e.Name()
		if len(name) >= 6 {
			var v uint
			if _, err := fmt.Sscanf(name[:6], "%06d", &v); err == nil && v > max {
				max = v
			}
		}
	}
	return max
}

func newMigrate(dsn string) (*migrate.Migrate, error) {
	// The embedded FS has files under "migrations/" subdirectory.
	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("create migration source: %w", err)
	}

	// golang-migrate pgx v5 driver expects "pgx5://" scheme.
	pgxDSN := "pgx5" + dsn[len("postgres"):]

	m, err := migrate.NewWithSourceInstance("iofs", source, pgxDSN)
	if err != nil {
		return nil, fmt.Errorf("create migrate instance: %w", err)
	}

	return m, nil
}
