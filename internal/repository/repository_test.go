//go:build integration

package repository_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/repository"
)

var testPool *database.Pool

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	dbCfg := database.Config{
		Host: "127.0.0.1", Port: 5432, Name: "vectis",
		User: "postgres", Password: "vectis_dev_super",
	}
	pool, err := database.NewPool(ctx, dbCfg, logger)
	if err != nil {
		slog.Error("skipping repository tests: cannot connect to postgres", "error", err)
		os.Exit(0)
	}
	testPool = pool
	code := m.Run()
	pool.Close()
	os.Exit(code)
}

func TestAPIKey_CRUD(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewAPIKeyRepo(testPool)

	adminRepo := repository.NewAdminRepo(testPool)
	admin, err := adminRepo.Create(ctx, repository.AdminCreate{
		Email:        "apikey-test@repo-test.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$dGVzdHNhbHQ$dGVzdGhhc2g",
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	defer adminRepo.Delete(ctx, admin.ID)

	key, rawKey, err := repo.Create(ctx, admin.ID, "test-key", nil)
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	if rawKey == "" || key.ID == "" {
		t.Fatal("expected non-empty key and ID")
	}

	got, err := repo.GetByID(ctx, key.ID)
	if err != nil {
		t.Fatalf("get api key: %v", err)
	}
	if got.Name != "test-key" {
		t.Errorf("name = %q, want test-key", got.Name)
	}

	keys, err := repo.ListByAdmin(ctx, admin.ID)
	if err != nil || len(keys) == 0 {
		t.Fatalf("list api keys: %v (count=%d)", err, len(keys))
	}

	if err := repo.Delete(ctx, key.ID); err != nil {
		t.Fatalf("delete api key: %v", err)
	}
}

func TestWebhook_CRUD(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewWebhookRepo(testPool)

	wh, err := repo.Create(ctx, repository.WebhookCreate{
		URL:    "https://example.com/hook",
		Events: []string{"domain.created", "mailbox.created"},
	})
	if err != nil {
		t.Fatalf("create webhook: %v", err)
	}
	defer repo.Delete(ctx, wh.ID)

	if wh.URL != "https://example.com/hook" {
		t.Errorf("url = %q", wh.URL)
	}

	hooks, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list webhooks: %v", err)
	}
	found := false
	for _, h := range hooks {
		if h.ID == wh.ID {
			found = true
		}
	}
	if !found {
		t.Error("created webhook not found in list")
	}
}

func TestAlert_CRUD(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewAlertRepo(testPool)

	alert, err := repo.Create(ctx, repository.AlertCreate{
		Severity: "warning",
		Source:   "test",
		Message:  "test alert",
	})
	if err != nil {
		t.Fatalf("create alert: %v", err)
	}

	got, err := repo.GetByID(ctx, alert.ID)
	if err != nil {
		t.Fatalf("get alert: %v", err)
	}
	if got.Message != "test alert" {
		t.Errorf("message = %q", got.Message)
	}

	if err := repo.Acknowledge(ctx, alert.ID); err != nil {
		t.Fatalf("acknowledge alert: %v", err)
	}

	alerts, err := repo.ListRecent(ctx, 10)
	if err != nil {
		t.Fatalf("list alerts: %v", err)
	}
	if len(alerts) == 0 {
		t.Error("expected at least one alert")
	}
}

func TestAdminDomain_CRUD(t *testing.T) {
	ctx := context.Background()

	adminRepo := repository.NewAdminRepo(testPool)
	domainRepo := repository.NewDomainRepo(testPool)
	adRepo := repository.NewAdminDomainRepo(testPool)

	admin, err := adminRepo.Create(ctx, repository.AdminCreate{
		Email:        "admindomain-test@repo-test.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$dGVzdHNhbHQ$dGVzdGhhc2g",
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	defer adminRepo.Delete(ctx, admin.ID)

	domain, err := domainRepo.Create(ctx, repository.DomainCreate{Name: "admin-domain-test.com"})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	defer domainRepo.Delete(ctx, domain.ID)

	if err := adRepo.Grant(ctx, admin.ID, domain.ID); err != nil {
		t.Fatalf("grant: %v", err)
	}

	domains, err := adRepo.ListDomainsByAdmin(ctx, admin.ID)
	if err != nil || len(domains) == 0 {
		t.Fatalf("list domains by admin: %v (count=%d)", err, len(domains))
	}

	if err := adRepo.Revoke(ctx, admin.ID, domain.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}
