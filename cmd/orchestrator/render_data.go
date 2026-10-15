package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/engine"
	"github.com/Veltara-Works/vectis/internal/repository"
)

type domainLister interface {
	List(ctx context.Context, activeOnly *bool) ([]repository.Domain, error)
}

type spamListLister interface {
	ListAll(ctx context.Context) ([]repository.SpamListJoined, error)
}

// renderData builds the template data for the compose and per-service config
// generators. It must load everything the templates read from the database,
// not just domains: the rspamd allow/block maps, settings.conf and
// rspamd.local.lua also render the per-domain spam lists. Leaving them out
// emptied every operator's lists on each update and self-heal (#281).
//
// A failure to load the spam lists fails the render rather than writing empty
// maps. The exception is a schema older than migration 000016, where the
// table does not exist yet and so no entries can exist either.
func renderData(ctx context.Context, cfg *config.VectisConfig, secrets *config.VectisSecrets,
	domains domainLister, spamLists spamListLister, releaseTag string) (*engine.TemplateData, error) {
	ds, err := domains.List(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}
	entries, err := spamLists.ListAll(ctx)
	if err != nil && !isUndefinedTable(err) {
		return nil, fmt.Errorf("list spam list entries: %w", err)
	}

	data := engine.NewTemplateData(cfg, secrets, ds)
	data.SpamListEntries = engine.SpamListInfosFrom(entries)
	if releaseTag != "" {
		data.Version = releaseTag
	}
	return data, nil
}

// isUndefinedTable reports whether err is Postgres SQLSTATE 42P01.
func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}
