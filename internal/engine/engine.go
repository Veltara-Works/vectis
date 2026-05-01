package engine

import (
	"bytes"
	"embed"
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

//go:embed templates
var templatesFS embed.FS

// TemplateData holds all data needed to render config templates.
type TemplateData struct {
	// Vectis release version, used to pin image tags in the generated compose
	// file so rollback can restore the exact prior version. "dev" for local
	// builds — the orchestrator pull logic skips tags with no registry prefix.
	Version string

	// From config.yaml
	Hostname   string
	TLS        config.TLSConfig
	ClamAV     ClamAVKnobs
	Rspamd     config.RspamdConfig
	Postfix    config.PostfixConfig
	Dovecot    config.DovecotConfig
	Logging    config.LoggingConfig
	Admin      config.AdminConfig
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

// ClamAVKnobs holds the resolved per-profile knobs for the ClamAV sidecar.
// The raw config.yaml exposes only `clamav.profile`; this struct turns that
// single string into the concrete numbers needed by clamd.conf and the
// compose mem_limit. Resolved once at render time via NewTemplateData so
// templates can reference `.ClamAV.MaxThreads` etc. without re-deriving.
//
// Profile semantics per ADR-007:
//   none       — container omitted entirely (knobs unused)
//   dev        — laptop / single-developer; minimal RAM
//   small      — 1-domain VPS; balanced
//   production — multi-domain; default for typical installs
//   enterprise — high-volume; tuned for throughput
type ClamAVKnobs struct {
	Profile         string // "none" | "dev" | "small" | "production" | "enterprise"
	MaxThreads      int    // clamd.conf MaxThreads
	StreamMaxLength string // clamd.conf StreamMaxLength, e.g. "25M"
	MaxScanSize     string // clamd.conf MaxScanSize
	MaxFileSize     string // clamd.conf MaxFileSize
	MemLimit        string // compose mem_limit, e.g. "1500m"
}

// resolveClamAVKnobs maps a clamav.profile string to concrete clamd.conf
// settings + compose mem_limit. The "none" profile returns zero-value knobs
// (template gates already skip rendering when profile == "none").
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
		Version:    version.Version,
		Hostname:   cfg.Hostname,
		TLS:        cfg.TLS,
		ClamAV:     resolveClamAVKnobs(cfg.ClamAV.Profile),
		Rspamd:     cfg.Rspamd,
		Postfix:    cfg.Postfix,
		Dovecot:    dovecot,
		Logging:    cfg.Logging,
		Admin:      cfg.Admin,
		Webmail:       cfg.Webmail,
		Observability: cfg.Observability,
		RateLimits:    rateLimits,
		Database: secrets.Database,
		Valkey:   secrets.Valkey,
		API:      secrets.API,
		Cluster:  cfg.Cluster,
		Domains:    domains,
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

// funcMap provides custom template functions.
var funcMap = template.FuncMap{
	"upper": strings.ToUpper,
	"lower": strings.ToLower,
	"hasFloat": func(p *float64) bool { return p != nil },
	"hasBool":  func(p *bool) bool { return p != nil },
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
		var mode os.FileMode
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
		// Derive a Grafana admin password from the API secret rather than
		// exposing the API secret itself. Use first 32 chars as a stable
		// derived password.
		secrets["grafana_admin_password"] = data.API.Secret[:min(32, len(data.API.Secret))]
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
