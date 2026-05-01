// render-configs is a one-shot recovery CLI that renders the per-service
// config templates (postfix, dovecot, rspamd, traefik, ...) the same way
// orchestrator's startup self-heal would, but without firing any of the
// recreate-services side effects. Used to bootstrap or repair a host whose
// config volumes are partial or stale.
//
// It mirrors cmd/orchestrator/main.go's SetConfigGenerator closure: load
// config + secrets, query domains, call engine.NewTemplateData +
// engine.Generate, write everything except docker-compose.yml.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/engine"
	"github.com/Veltara-Works/vectis/internal/repository"
)

func main() {
	var (
		configDir = flag.String("config-dir", "/etc/vectis", "directory containing config.yaml + secrets.yaml")
		outDir    = flag.String("out", "/var/vectis/generated", "output directory")
		only      = flag.String("only", "", "comma-separated subdirs to render (e.g. rspamd,postfix); empty = all")
		dryRun    = flag.Bool("dry-run", false, "list files that would be written, don't write")
	)
	flag.Parse()

	cfg, secrets, err := config.LoadAll(*configDir)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		secrets.Database.APIUser,
		secrets.Database.APIPassword,
		secrets.Database.Host,
		secrets.Database.Port,
		secrets.Database.Name,
	)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("connect postgres: %v", err)
	}
	defer pool.Close()

	domains, err := repository.NewDomainRepo(pool).List(ctx, nil)
	if err != nil {
		log.Fatalf("list domains: %v", err)
	}

	data := engine.NewTemplateData(cfg, secrets, domains)
	files, err := engine.Generate(data)
	if err != nil {
		log.Fatalf("render templates: %v", err)
	}

	var prefixes []string
	if *only != "" {
		for _, p := range strings.Split(*only, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				prefixes = append(prefixes, p)
			}
		}
	}

	matches := func(rel string) bool {
		if len(prefixes) == 0 {
			return true
		}
		for _, p := range prefixes {
			if rel == p || strings.HasPrefix(rel, p+"/") {
				return true
			}
		}
		return false
	}

	written := 0
	for _, f := range files {
		if f.RelPath == "docker-compose.yml" {
			continue
		}
		if !matches(f.RelPath) {
			continue
		}
		if *dryRun {
			fmt.Printf("would write %s (%d bytes)\n", f.RelPath, len(f.Content))
			written++
			continue
		}
		outPath := filepath.Join(*outDir, f.RelPath)
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			log.Fatalf("mkdir %s: %v", filepath.Dir(outPath), err)
		}
		mode := f.Mode
		if mode == 0 {
			mode = 0600
		}
		if err := os.WriteFile(outPath, f.Content, mode); err != nil {
			log.Fatalf("write %s: %v", outPath, err)
		}
		fmt.Printf("wrote %s (%d bytes)\n", f.RelPath, len(f.Content))
		written++
	}
	fmt.Printf("done — %d files\n", written)
}
