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
	ClamAV     config.ClamAVConfig
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
		ClamAV:     cfg.ClamAV,
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
