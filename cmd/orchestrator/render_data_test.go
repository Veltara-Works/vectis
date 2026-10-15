package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/engine"
	"github.com/Veltara-Works/vectis/internal/repository"
)

type fakeDomains struct {
	domains []repository.Domain
	err     error
}

func (f fakeDomains) List(context.Context, *bool) ([]repository.Domain, error) {
	return f.domains, f.err
}

type fakeSpamLists struct {
	entries []repository.SpamListJoined
	err     error
}

func (f fakeSpamLists) ListAll(context.Context) ([]repository.SpamListJoined, error) {
	return f.entries, f.err
}

func testCfg() (*config.VectisConfig, *config.VectisSecrets) {
	return &config.VectisConfig{Hostname: "mail.example.com"}, &config.VectisSecrets{}
}

// The regression in #281: the orchestrator rendered without the spam lists,
// so every update emptied the rspamd allow/block maps.
func TestRenderDataIncludesSpamLists(t *testing.T) {
	cfg, secrets := testCfg()
	domains := fakeDomains{domains: []repository.Domain{{ID: "d1", Name: "example.com", Active: true}}}
	lists := fakeSpamLists{entries: []repository.SpamListJoined{
		{DomainName: "example.com", Kind: "allow", Scope: "domain", Pattern: "trusted.example"},
		{DomainName: "example.com", Kind: "block", Scope: "email", Pattern: "phisher@evil.example"},
	}}

	data, err := renderData(context.Background(), cfg, secrets, domains, lists, "v9.9.9")
	if err != nil {
		t.Fatalf("renderData: %v", err)
	}
	if data.Version != "v9.9.9" {
		t.Errorf("Version = %q, want v9.9.9", data.Version)
	}
	want := []engine.SpamListInfo{
		{DomainName: "example.com", Kind: "allow", Scope: "domain", Pattern: "trusted.example"},
		{DomainName: "example.com", Kind: "block", Scope: "email", Pattern: "phisher@evil.example"},
	}
	if fmt.Sprint(data.SpamListEntries) != fmt.Sprint(want) {
		t.Fatalf("SpamListEntries = %v, want %v", data.SpamListEntries, want)
	}

	// And they reach the rendered maps.
	data.Database = config.DatabaseSecrets{Host: "postgres", Port: 5432, Name: "vectis"}
	files, err := engine.Generate(data)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	maps := map[string]string{
		"rspamd/maps/allow_domain.map": "example.com:trusted.example",
		"rspamd/maps/block_email.map":  "example.com:phisher@evil.example",
	}
	for _, f := range files {
		if line, ok := maps[f.RelPath]; ok {
			if !strings.Contains(string(f.Content), line) {
				t.Errorf("%s missing %q:\n%s", f.RelPath, line, f.Content)
			}
			delete(maps, f.RelPath)
		}
	}
	for path := range maps {
		t.Errorf("%s not rendered", path)
	}
}

// A failed lookup must fail the render instead of writing empty maps.
func TestRenderDataFailsWhenSpamListsCannotBeLoaded(t *testing.T) {
	cfg, secrets := testCfg()
	_, err := renderData(context.Background(), cfg, secrets, fakeDomains{},
		fakeSpamLists{err: errors.New("connection reset")}, "")
	if err == nil {
		t.Fatal("renderData succeeded with a spam-list load error; it would render empty maps")
	}
}

// Before migration 000016 the table does not exist, so no lists can exist yet.
func TestRenderDataToleratesMissingSpamListTable(t *testing.T) {
	cfg, secrets := testCfg()
	missing := fmt.Errorf("list all spam list entries: %w", &pgconn.PgError{Code: "42P01"})
	data, err := renderData(context.Background(), cfg, secrets, fakeDomains{},
		fakeSpamLists{err: missing}, "")
	if err != nil {
		t.Fatalf("renderData: %v", err)
	}
	if len(data.SpamListEntries) != 0 {
		t.Errorf("SpamListEntries = %v, want none", data.SpamListEntries)
	}
}

func TestRenderDataFailsWhenDomainsCannotBeLoaded(t *testing.T) {
	cfg, secrets := testCfg()
	_, err := renderData(context.Background(), cfg, secrets,
		fakeDomains{err: errors.New("connection reset")}, fakeSpamLists{}, "")
	if err == nil {
		t.Fatal("renderData succeeded with a domain load error")
	}
}
