package engine

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/repository"
	"github.com/Veltara-Works/vectis/internal/version"
)

// inboundNotifyTokenLabel is the HMAC message that derives the Postfix
// inbound-notify token from the master API secret. Changing it rotates the
// token; the API and the generated script must always use the same label.
const inboundNotifyTokenLabel = "vectis-inbound-notify-v1"

// grafanaAdminPasswordLabel derives Grafana's admin password from the master
// API secret. Like the inbound-notify token it is a one-way HMAC of the secret,
// never a substring of it: the value is written to an on-disk secrets file and
// handed to Grafana, so it must not be reversible into the master secret (which
// also keys sessions, TOTP, webhooks and backup encryption).
const grafanaAdminPasswordLabel = "vectis-grafana-admin-v1"

// DeriveInboundNotifyToken derives the token the Postfix inbound-notify script
// presents to POST /internal/inbound, as HMAC-SHA256(apiSecret, label). It is
// deliberately NOT the master API secret: the script is world-readable inside
// the postfix container (it runs as user=nobody via a Postfix pipe, so it must
// be readable by that user), and embedding the master secret there exposes the
// key that also protects sessions, TOTP, webhooks and import encryption. The
// derived token only authorises inbound notifications. The API computes the
// same value at startup, so no storage or migration is needed.
func DeriveInboundNotifyToken(apiSecret string) string {
	mac := hmac.New(sha256.New, []byte(apiSecret))
	mac.Write([]byte(inboundNotifyTokenLabel))
	return hex.EncodeToString(mac.Sum(nil))
}

// DeriveGrafanaAdminPassword derives Grafana's admin password as
// HMAC-SHA256(apiSecret, label), hex-encoded (64 chars). Deterministic so no
// storage/migration is needed, and one-way so the on-disk secrets file and
// Grafana's stored credential cannot be reversed into the master API secret.
// Replaces the prior data.API.Secret[:32] substring, which exposed up to the
// entire secret verbatim (api.secret is validated >= 32 chars).
func DeriveGrafanaAdminPassword(apiSecret string) string {
	mac := hmac.New(sha256.New, []byte(apiSecret))
	mac.Write([]byte(grafanaAdminPasswordLabel))
	return hex.EncodeToString(mac.Sum(nil))
}

//go:embed templates
var templatesFS embed.FS

// TemplateData holds all data needed to render config templates.
type TemplateData struct {
	// Vectis release version, used to pin image tags in the generated compose
	// file so rollback can restore the exact prior version. "dev" for local
	// builds — the orchestrator pull logic skips tags with no registry prefix.
	Version string

	// From config.yaml
	Hostname      string
	TLS           config.TLSConfig
	Resources     ResourceKnobs
	ClamAV        ClamAVKnobs
	Rspamd        config.RspamdConfig
	Postfix       config.PostfixConfig
	Dovecot       config.DovecotConfig
	Logging       config.LoggingConfig
	Admin         config.AdminConfig
	Webmail       config.WebmailConfig
	Observability config.ObservabilityConfig
	RateLimits    config.RateLimitConfig

	// From secrets.yaml
	Database config.DatabaseSecrets
	Valkey   config.ValkeySecrets
	API      config.APISecrets

	// Clustering
	Cluster config.ClusterConfig

	// From Postgres (queried at generation time)
	Domains []repository.Domain

	// SpamListEntries is the flat union of every per-domain allow/block
	// list entry across all domains. Optional — when empty (e.g. fresh
	// install, Free tier with no Pro license, no entries created yet) the
	// rspamd multimap files render empty and the prefilter is a no-op.
	// Populated by callers after NewTemplateData; the engine package does
	// not query Postgres directly.
	SpamListEntries []SpamListInfo
}

// InboundNotifyToken is the scoped token embedded in the Postfix inbound-notify
// script, derived from the master API secret (never the secret itself — see
// DeriveInboundNotifyToken). Exposed as a method so templates can reference
// {{ .InboundNotifyToken }} without every TemplateData construction site having
// to compute it.
func (d TemplateData) InboundNotifyToken() string {
	return DeriveInboundNotifyToken(d.API.Secret)
}

// SpamListInfo is a denormalized view of a domain_spam_lists row used by
// rspamd templates. DomainName is included so the template can build
// per-recipient-domain composite keys without a join. Kept in the engine
// package to avoid an import cycle on internal/repository for the embed
// templates.
type SpamListInfo struct {
	DomainName string
	Kind       string // "allow" | "block"
	Scope      string // "email" | "domain"
	Pattern    string
}

// ResourceKnobs holds the resolved per-service mem_limit ceilings for
// every container in the stack. The raw config.yaml exposes only
// `resources.profile`; this struct turns that single string into the
// concrete numbers needed by compose's `mem_limit` directive. Resolved
// once at render time via NewTemplateData so templates can reference
// `.Resources.APIMemLimit` etc. without re-deriving.
//
// Profile semantics (P7-H1 / audit 2026-05-17):
//
//	dev        — laptop / 2 GB VPS; minimal ceilings (~1.8 GB base)
//	small      — single-domain 4 GB VPS; default for fresh installs (~3.5 GB base)
//	production — multi-domain 8 GB VPS; matches audit recommendation (~6.7 GB base)
//	enterprise — 16 GB+; doubled from production for high-volume sites (~13.5 GB base)
//
// "Base" excludes ClamAV (which has its own profile) and the optional
// webmail / Loki / Promtail / Grafana / cert-extractor / pgbouncer
// services. See installation.md for the full RAM-vs-feature matrix.
//
// ValkeyMaxMemory is the in-server `--maxmemory` flag (allkeys-lru policy)
// and intentionally sits well below ValkeyMemLimit so valkey LRU-evicts
// gracefully before the cgroup OOM-kills the process.
type ResourceKnobs struct {
	Profile               string
	APIMemLimit           string
	OrchestratorMemLimit  string
	TraefikMemLimit       string
	PostfixMemLimit       string
	DovecotMemLimit       string
	RspamdMemLimit        string
	PostgresMemLimit      string
	ValkeyMemLimit        string
	ValkeyMaxMemory       string
	WebmailMemLimit       string
	LokiMemLimit          string
	PromtailMemLimit      string
	GrafanaMemLimit       string
	CertExtractorMemLimit string
	PgBouncerMemLimit     string
}

// resolveResourceKnobs maps a resources.profile string to concrete per-service
// mem_limit values. Empty string defaults to "small" — that's the right call
// for fresh installs on the documented 4 GB-VPS minimum. Unknown profiles
// also fall through to "small" to keep behaviour conservative.
func resolveResourceKnobs(profile string) ResourceKnobs {
	switch profile {
	case "dev":
		return ResourceKnobs{
			Profile:               "dev",
			APIMemLimit:           "256m",
			OrchestratorMemLimit:  "128m",
			TraefikMemLimit:       "128m",
			PostfixMemLimit:       "128m",
			DovecotMemLimit:       "256m",
			RspamdMemLimit:        "256m",
			PostgresMemLimit:      "512m",
			ValkeyMemLimit:        "128m",
			ValkeyMaxMemory:       "64mb",
			WebmailMemLimit:       "256m",
			LokiMemLimit:          "256m",
			PromtailMemLimit:      "64m",
			GrafanaMemLimit:       "256m",
			CertExtractorMemLimit: "32m",
			PgBouncerMemLimit:     "64m",
		}
	case "production":
		return ResourceKnobs{
			Profile:               "production",
			APIMemLimit:           "1g",
			OrchestratorMemLimit:  "512m",
			TraefikMemLimit:       "256m",
			PostfixMemLimit:       "512m",
			DovecotMemLimit:       "1g",
			RspamdMemLimit:        "1g",
			PostgresMemLimit:      "2g",
			ValkeyMemLimit:        "512m",
			ValkeyMaxMemory:       "256mb",
			WebmailMemLimit:       "512m",
			LokiMemLimit:          "512m",
			PromtailMemLimit:      "256m",
			GrafanaMemLimit:       "512m",
			CertExtractorMemLimit: "64m",
			PgBouncerMemLimit:     "128m",
		}
	case "enterprise":
		return ResourceKnobs{
			Profile:               "enterprise",
			APIMemLimit:           "2g",
			OrchestratorMemLimit:  "1g",
			TraefikMemLimit:       "512m",
			PostfixMemLimit:       "1g",
			DovecotMemLimit:       "2g",
			RspamdMemLimit:        "2g",
			PostgresMemLimit:      "4g",
			ValkeyMemLimit:        "1g",
			ValkeyMaxMemory:       "512mb",
			WebmailMemLimit:       "1g",
			LokiMemLimit:          "1g",
			PromtailMemLimit:      "512m",
			GrafanaMemLimit:       "1g",
			CertExtractorMemLimit: "128m",
			PgBouncerMemLimit:     "256m",
		}
	default: // "small" or empty or unknown — conservative fresh-install default
		return ResourceKnobs{
			Profile:               "small",
			APIMemLimit:           "512m",
			OrchestratorMemLimit:  "256m",
			TraefikMemLimit:       "128m",
			PostfixMemLimit:       "256m",
			DovecotMemLimit:       "512m",
			RspamdMemLimit:        "512m",
			PostgresMemLimit:      "1g",
			ValkeyMemLimit:        "256m",
			ValkeyMaxMemory:       "128mb",
			WebmailMemLimit:       "512m",
			LokiMemLimit:          "256m",
			PromtailMemLimit:      "128m",
			GrafanaMemLimit:       "256m",
			CertExtractorMemLimit: "64m",
			PgBouncerMemLimit:     "128m",
		}
	}
}

// ClamAVKnobs holds the resolved per-profile knobs for the ClamAV sidecar.
// The raw config.yaml exposes only `clamav.profile`; this struct turns that
// single string into the concrete numbers needed by clamd.conf and the
// compose mem_limit. Resolved once at render time via NewTemplateData so
// templates can reference `.ClamAV.MaxThreads` etc. without re-deriving.
//
// Profile semantics per ADR-007:
//
//	none       — container omitted entirely (knobs unused)
//	dev        — laptop / single-developer; minimal RAM
//	small      — 1-domain VPS; balanced
//	production — multi-domain; default for typical installs
//	enterprise — high-volume; tuned for throughput
type ClamAVKnobs struct {
	Profile         string // "none" | "dev" | "small" | "production" | "enterprise"
	MaxThreads      int    // clamd.conf MaxThreads
	StreamMaxLength string // clamd.conf StreamMaxLength, e.g. "25M"
	MaxScanSize     string // clamd.conf MaxScanSize
	MaxFileSize     string // clamd.conf MaxFileSize
	MemLimit        string // compose mem_limit, e.g. "1500m"
}

// resolveClamAVKnobs maps a clamav.profile string to concrete clamd.conf
// settings + compose mem_limit. The "none" profile returns zero-value knobs:
// clamd.conf is still rendered (Generate walks every template), but the
// clamd.conf template omits each knob line when its value is zero/empty so
// the file stays parseable even though the container is never started (#44).
func resolveClamAVKnobs(profile string) ClamAVKnobs {
	switch profile {
	case "dev":
		return ClamAVKnobs{
			Profile:         "dev",
			MaxThreads:      2,
			StreamMaxLength: "20M",
			MaxScanSize:     "50M",
			MaxFileSize:     "20M",
			MemLimit:        "1g",
		}
	case "small":
		return ClamAVKnobs{
			Profile:         "small",
			MaxThreads:      4,
			StreamMaxLength: "25M",
			MaxScanSize:     "100M",
			MaxFileSize:     "25M",
			MemLimit:        "1500m",
		}
	case "production":
		return ClamAVKnobs{
			Profile:         "production",
			MaxThreads:      8,
			StreamMaxLength: "50M",
			MaxScanSize:     "150M",
			MaxFileSize:     "50M",
			MemLimit:        "2g",
		}
	case "enterprise":
		return ClamAVKnobs{
			Profile:         "enterprise",
			MaxThreads:      16,
			StreamMaxLength: "100M",
			MaxScanSize:     "300M",
			MaxFileSize:     "100M",
			MemLimit:        "3g",
		}
	default: // "none" or anything else
		return ClamAVKnobs{Profile: "none"}
	}
}

// NewTemplateData builds TemplateData from config, secrets, and domain list.
func NewTemplateData(cfg *config.VectisConfig, secrets *config.VectisSecrets, domains []repository.Domain) *TemplateData {
	rateLimits := cfg.RateLimits
	if rateLimits.AuthAverage == 0 {
		rateLimits = config.DefaultRateLimits()
	}

	dovecot := cfg.Dovecot
	dovecot.ValkeyHost = secrets.Valkey.Host
	dovecot.ValkeyPort = secrets.Valkey.Port

	return &TemplateData{
		Version:       version.Version,
		Hostname:      cfg.Hostname,
		TLS:           cfg.TLS,
		Resources:     resolveResourceKnobs(cfg.Resources.Profile),
		ClamAV:        resolveClamAVKnobs(cfg.ClamAV.Profile),
		Rspamd:        cfg.Rspamd,
		Postfix:       cfg.Postfix,
		Dovecot:       dovecot,
		Logging:       cfg.Logging,
		Admin:         cfg.Admin,
		Webmail:       cfg.Webmail,
		Observability: cfg.Observability,
		RateLimits:    rateLimits,
		Database:      secrets.Database,
		Valkey:        secrets.Valkey,
		API:           secrets.API,
		Cluster:       cfg.Cluster,
		Domains:       domains,
	}
}

// GeneratedFile represents a single rendered config file.
type GeneratedFile struct {
	// RelPath is the path relative to the output root (e.g., "postfix/main.cf").
	RelPath string
	Content []byte
	// Mode is the file permission mode. Zero means use the default (0600).
	// Shell scripts and other files that need to be readable/executable by
	// non-root processes inside containers (e.g. postgres init scripts) are
	// rendered with a more permissive mode.
	Mode os.FileMode
}

// dovecotMailVars converts legacy Dovecot 2.3 %d/%n/%u variables to the
// 2.4 %{user|...} expansion syntax (all one-letter variables were removed in 2.4).
func dovecotMailVars(s string) string {
	s = strings.ReplaceAll(s, "%d", "%{user | domain}")
	s = strings.ReplaceAll(s, "%n", "%{user | username}")
	s = strings.ReplaceAll(s, "%u", "%{user}")
	return s
}

// splitMailLocation splits a legacy mail_location ("maildir:/path/%d/%n/Maildir")
// into its driver ("maildir") and path. Dovecot 2.4 replaced the combined
// mail_location with separate mail_driver and mail_path settings.
func splitMailLocation(loc string) (driver, path string) {
	if i := strings.Index(loc, ":"); i >= 0 {
		return loc[:i], loc[i+1:]
	}
	return loc, ""
}

// funcMap provides custom template functions.
var funcMap = template.FuncMap{
	"upper":    strings.ToUpper,
	"lower":    strings.ToLower,
	"hasFloat": func(p *float64) bool { return p != nil },
	"hasBool":  func(p *bool) bool { return p != nil },
	// Dovecot 2.4 mail_location → mail_driver/mail_path/mail_home conversion.
	"mailDriver": func(loc string) string { d, _ := splitMailLocation(loc); return d },
	"mailPath":   func(loc string) string { _, p := splitMailLocation(loc); return dovecotMailVars(p) },
	"mailHome": func(loc string) string {
		_, p := splitMailLocation(loc)
		return dovecotMailVars(strings.TrimSuffix(p, "/Maildir"))
	},
	"derefFloat": func(p *float64) float64 {
		if p == nil {
			return 0
		}
		return *p
	},
	"derefBool": func(p *bool) bool {
		if p == nil {
			return false
		}
		return *p
	},
}

// Generate renders all templates and returns the generated files.
func Generate(data *TemplateData) ([]GeneratedFile, error) {
	var files []GeneratedFile

	err := fs.WalkDir(templatesFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".tmpl") {
			return nil
		}
		// Secret files are written exclusively by WriteSecrets (mode 0600, with
		// values that are loaded or one-way-derived — never a master-secret
		// substring). Skipping templates/secrets/ here keeps Generate/WriteFiles
		// from emitting a world-readable (0644) secret file or, worse, the API
		// secret prefix on every config apply. See WriteSecrets /
		// DeriveGrafanaAdminPassword.
		if strings.HasPrefix(path, "templates/secrets/") {
			return nil
		}

		content, err := fs.ReadFile(templatesFS, path)
		if err != nil {
			return fmt.Errorf("read template %s: %w", path, err)
		}

		tmpl, err := template.New(filepath.Base(path)).Funcs(funcMap).Parse(string(content))
		if err != nil {
			return fmt.Errorf("parse template %s: %w", path, err)
		}

		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			return fmt.Errorf("execute template %s: %w", path, err)
		}

		// Strip "templates/" prefix and ".tmpl" suffix to get output path.
		relPath := strings.TrimPrefix(path, "templates/")
		relPath = strings.TrimSuffix(relPath, ".tmpl")

		// Shell scripts must be readable + executable inside their container
		// (e.g. postgres `/docker-entrypoint-initdb.d/01-init-users.sh`).
		// Everything else is 0644 — the files are bind-mounted into containers
		// owned by various non-root users (rspamd, www-data, ...), so 0600
		// would silently break readability inside the container. Caught by
		// the v0.1.7-rc2 webmail-skin walkthrough where Roundcube's skin
		// loader silently failed to read meta.json (mode 0600, root-only),
		// causing `extends: elastic` to never register and templates to
		// 404 with no clear error.
		mode := os.FileMode(0644)
		if strings.HasSuffix(relPath, ".sh") {
			mode = 0755
		}

		files = append(files, GeneratedFile{
			RelPath: relPath,
			Content: buf.Bytes(),
			Mode:    mode,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	return files, nil
}

// WriteFiles writes generated files to the given output directory.
func WriteFiles(outputDir string, files []GeneratedFile) error {
	for _, f := range files {
		outPath := filepath.Join(outputDir, f.RelPath)

		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return fmt.Errorf("create directory for %s: %w", f.RelPath, err)
		}

		mode := f.Mode
		if mode == 0 {
			mode = 0600
		}
		if err := os.WriteFile(outPath, f.Content, mode); err != nil {
			return fmt.Errorf("write %s: %w", f.RelPath, err)
		}
	}
	return nil
}

// WriteSecrets writes individual Docker secret files expected by docker-compose.
// Each secret is written as a single-value file under secretsDir (e.g.
// /var/vectis/generated/secrets/valkey_password). These files are referenced
// by the Docker Compose `secrets:` section.
func WriteSecrets(secretsDir string, data *TemplateData) error {
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return fmt.Errorf("create secrets directory: %w", err)
	}

	secrets := map[string]string{
		"valkey_password": data.Valkey.Password,
	}

	if data.Observability.GrafanaEnabled && data.API.Secret != "" {
		// One-way HMAC of the API secret (NOT a substring of it) so the on-disk
		// secrets file and Grafana's stored credential can't be reversed into
		// the master secret. See DeriveGrafanaAdminPassword.
		secrets["grafana_admin_password"] = DeriveGrafanaAdminPassword(data.API.Secret)
	}

	for name, value := range secrets {
		path := filepath.Join(secretsDir, name)
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			return fmt.Errorf("write secret %s: %w", name, err)
		}
	}

	return nil
}

// DiffFiles compares generated files against what's currently on disk.
// Returns a list of files that differ.
func DiffFiles(outputDir string, files []GeneratedFile) ([]FileDiff, error) {
	var diffs []FileDiff

	for _, f := range files {
		outPath := filepath.Join(outputDir, f.RelPath)
		existing, err := os.ReadFile(outPath)
		if err != nil {
			if os.IsNotExist(err) {
				diffs = append(diffs, FileDiff{
					RelPath: f.RelPath,
					Status:  "new",
				})
				continue
			}
			return nil, fmt.Errorf("read existing %s: %w", f.RelPath, err)
		}

		if !bytes.Equal(existing, f.Content) {
			diffs = append(diffs, FileDiff{
				RelPath: f.RelPath,
				Status:  "modified",
			})
		}
	}

	return diffs, nil
}

// FileDiff describes a difference between generated and on-disk config.
type FileDiff struct {
	RelPath string `json:"path"`
	Status  string `json:"status"` // "new" or "modified"
}
