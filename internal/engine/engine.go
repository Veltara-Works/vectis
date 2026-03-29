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
)

//go:embed templates
var templatesFS embed.FS

// TemplateData holds all data needed to render config templates.
type TemplateData struct {
	// From config.yaml
	Hostname string
	TLS      config.TLSConfig
	ClamAV   config.ClamAVConfig
	Rspamd   config.RspamdConfig
	Postfix  config.PostfixConfig
	Dovecot  config.DovecotConfig
	Logging  config.LoggingConfig
	Admin    config.AdminConfig

	// From secrets.yaml
	Database   config.DatabaseSecrets
	Valkey     config.ValkeySecrets
	API        config.APISecrets
	Cloudflare *config.CloudflareSecrets

	// From Postgres (queried at generation time)
	Domains []repository.Domain
}

// NewTemplateData builds TemplateData from config, secrets, and domain list.
func NewTemplateData(cfg *config.VectisConfig, secrets *config.VectisSecrets, domains []repository.Domain) *TemplateData {
	return &TemplateData{
		Hostname: cfg.Hostname,
		TLS:      cfg.TLS,
		ClamAV:   cfg.ClamAV,
		Rspamd:   cfg.Rspamd,
		Postfix:  cfg.Postfix,
		Dovecot:  cfg.Dovecot,
		Logging:  cfg.Logging,
		Admin:    cfg.Admin,
		Database:   secrets.Database,
		Valkey:     secrets.Valkey,
		API:        secrets.API,
		Cloudflare: secrets.Cloudflare,
		Domains:    domains,
	}
}

// GeneratedFile represents a single rendered config file.
type GeneratedFile struct {
	// RelPath is the path relative to the output root (e.g., "postfix/main.cf").
	RelPath string
	Content []byte
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

		files = append(files, GeneratedFile{
			RelPath: relPath,
			Content: buf.Bytes(),
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

		if err := os.WriteFile(outPath, f.Content, 0600); err != nil {
			return fmt.Errorf("write %s: %w", f.RelPath, err)
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
