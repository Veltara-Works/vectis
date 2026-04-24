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
	ComposePaths       []string      // Ordered list of docker-compose files; multiple are merged via -f flags
	ReleaseChannelURL  string        // URL of the release manifest (versions.json) consulted during Plan; empty disables lookup
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
		ComposePaths:       []string{"/etc/vectis/docker-compose.yml"},
		ReleaseChannelURL:  DefaultReleaseChannelURL,
		DBHost:             "postgres",
		DBPort:             5432,
		DBName:             "vectis",
		DBUser:             "vectis_api",
	}
}

// composeFileArgs returns the ordered -f flag pairs needed to run docker compose
// across all configured compose files. Expands ["a.yml","b.yml"] to
// ["-f","a.yml","-f","b.yml"].
func (c Config) composeFileArgs() []string {
	out := make([]string, 0, 2*len(c.ComposePaths))
	for _, p := range c.ComposePaths {
		out = append(out, "-f", p)
	}
	return out
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
}

// VectisImageServices enumerates the services whose image tag tracks the
// Vectis release tag — i.e. the set that participates in Plan/Apply upgrades.
// Must stay in sync with the `image: ghcr.io/veltara-works/vectis-*` lines in
// templates/docker-compose.yml.tmpl; config_test enforces this invariant.
//
// Distinct from ServiceStartOrder on purpose: start order is about dependency
// ordering (postgres → valkey → mail services → api), while this list is about
// "which containers get their tags bumped when the user clicks Apply". Pre-rc33
// the two were conflated, so `orchestrator` and `cert-extractor` — both in the
// compose but not in the start list — silently fell out of Plan.Changes and
// got stranded on the old version post-Apply.
var VectisImageServices = []string{
	"api",
	"orchestrator",
	"postfix",
	"dovecot",
	"rspamd",
	"clamav",
	"cert-extractor",
}

// VectisImageServicesExcludingSelf returns VectisImageServices minus
// "orchestrator". Apply's Phase 4.3 uses this list to issue `compose up -d`
// for every upgradable service EXCEPT the orchestrator itself. The
// orchestrator's self-replacement is handed off to a detached helper
// container in Phase 4.4 — the only way around the self-kill race where
// `docker compose up -d` executed inside the orchestrator gets SIGTERM'd
// when the daemon starts swapping the orchestrator container (GA blocker #9,
// fixed rc36).
func VectisImageServicesExcludingSelf() []string {
	out := make([]string, 0, len(VectisImageServices)-1)
	for _, s := range VectisImageServices {
		if s == "orchestrator" {
			continue
		}
		out = append(out, s)
	}
	return out
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

// DataServices are services that must keep running through any operation that
// could fail midway. Rollback phase 2 (psql restore) needs postgres reachable;
// stopping it earlier makes restore impossible and leaves the stack unrecoverable.
// Valkey is kept for state-sync reasons (orchestrator writes state to it).
var DataServices = map[string]bool{
	"postgres": true,
	"valkey":   true,
}

// NonDataStopOrder returns the stop order for phases that must not disrupt the
// data layer: apply's phase 4.2 (stop-before-compose) and rollback's phase 1
// (stop-before-restore) both use it. Same set as ServiceStopOrder minus the
// DataServices.
func NonDataStopOrder() []string {
	full := ServiceStopOrder()
	out := make([]string, 0, len(full))
	for _, s := range full {
		if DataServices[s] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// NonDataStartOrder returns the start order for recovery paths that don't need
// to restart data services (because they were never stopped). Used by rollback's
// final restart and recover() in doRollback.
func NonDataStartOrder() []string {
	out := make([]string, 0, len(ServiceStartOrder))
	for _, s := range ServiceStartOrder {
		if DataServices[s] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// Deprecated aliases kept for backward compat; prefer NonData* names.
func RollbackStopOrder() []string  { return NonDataStopOrder() }
func RollbackStartOrder() []string { return NonDataStartOrder() }
