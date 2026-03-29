package orchestrator

import "time"

// Config holds the orchestrator's runtime configuration.
type Config struct {
	BearerToken        string        // Internal API bearer token
	ImagePullTimeout   time.Duration // Per-image pull timeout (default 300s)
	HealthCheckTimeout time.Duration // Default per-service health check timeout (default 120s)
	DBMigrationTimeout time.Duration // Total DB migration timeout (default 60s)
	ApplyTimeout       time.Duration // Overall apply cycle timeout (default 600s)
	RollbackTimeout    time.Duration // Total rollback timeout (default 300s)
	SnapshotDir        string        // Directory for pg_dump snapshots (default /var/vectis/snapshots)
	ComposePath        string        // Path to docker-compose.yml
	DBHost             string        // Postgres host (for pg_dump/psql)
	DBPort             int           // Postgres port
	DBName             string        // Postgres database name
	DBUser             string        // Postgres user for dump/restore
	DBPassword         string        // Postgres password for dump/restore
}

// DefaultConfig returns a Config with production defaults per Spec D.5.
func DefaultConfig() Config {
	return Config{
		ImagePullTimeout:   300 * time.Second,
		HealthCheckTimeout: 120 * time.Second,
		DBMigrationTimeout: 60 * time.Second,
		ApplyTimeout:       600 * time.Second,
		RollbackTimeout:    300 * time.Second,
		SnapshotDir:        "/var/vectis/snapshots",
		ComposePath:        "/etc/vectis/docker-compose.yml",
		DBHost:             "postgres",
		DBPort:             5432,
		DBName:             "vectis",
		DBUser:             "vectis_api",
	}
}

// ServiceHealthTimeouts defines per-service health check timeouts per Spec D.5.
var ServiceHealthTimeouts = map[string]time.Duration{
	"postgres": 30 * time.Second,
	"valkey":   15 * time.Second,
	"postfix":  30 * time.Second,
	"dovecot":  30 * time.Second,
	"rspamd":   60 * time.Second,
	"clamav":   180 * time.Second,
	"api":      30 * time.Second,
	"admin-ui": 15 * time.Second,
}

// ServiceStartOrder defines the dependency-first startup order per Spec D.6.
var ServiceStartOrder = []string{
	"postgres",
	"valkey",
	"postfix",
	"dovecot",
	"rspamd",
	"clamav",
	"api",
	"admin-ui",
}

// ServiceStopOrder returns the reverse of ServiceStartOrder (dependents first).
func ServiceStopOrder() []string {
	n := len(ServiceStartOrder)
	rev := make([]string, n)
	for i, s := range ServiceStartOrder {
		rev[n-1-i] = s
	}
	return rev
}
