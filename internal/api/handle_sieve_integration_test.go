//go:build integration

package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/repository"
)

func envOrSieve(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// TestGetMailboxCredentials_MintsAndRevokesSieveToken locks the ManageSieve
// admin credential path to the proven token-passdb mechanism (#112 importer,
// #114 impersonation). It asserts getMailboxCredentials:
//   - returns the mailbox's OWN address as the login (not the retired
//     user@domain*vectis-admin master user the deployed Dovecot never honoured),
//   - mints exactly one short-lived auth-token row tagged purpose="sieve", and
//   - hands back a revoke func that deletes that row.
func TestGetMailboxCredentials_MintsAndRevokesSieveToken(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	dbCfg := database.Config{
		Host:     envOrSieve("VECTIS_TEST_PG_HOST", "127.0.0.1"),
		Port:     5432,
		Name:     envOrSieve("VECTIS_TEST_PG_DB", "vectis"),
		User:     envOrSieve("VECTIS_TEST_PG_USER", "postgres"),
		Password: envOrSieve("VECTIS_TEST_PG_PASSWORD", "vectis_dev_super"),
	}
	pool, err := database.NewPool(ctx, dbCfg, logger)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	defer pool.Close()
	if err := database.RunMigrations(dbCfg.DSN(), logger); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	vk, err := database.NewValkeyClient(database.ValkeyConfig{
		Host:     envOrSieve("VECTIS_TEST_VK_HOST", "127.0.0.1"),
		Port:     6379,
		Password: envOrSieve("VECTIS_TEST_VK_PASSWORD", "vectis_dev_valkey"),
	}, logger)
	if err != nil {
		t.Fatalf("connect valkey: %v", err)
	}
	defer vk.Close()

	srv := New(pool, vk, Config{
		ListenAddr:   ":0",
		SessionTTL:   24,
		CookieSecret: "test-secret-32-chars-minimum-1234",
		Hostname:     "test.example.com",
		DKIMBasePath: t.TempDir(),
	}, logger)

	// Seed a domain + mailbox (unique domain name so reruns don't collide).
	domainRepo := repository.NewDomainRepo(pool)
	mailboxRepo := repository.NewMailboxRepo(pool)

	domainName := fmt.Sprintf("sieve-%d.example.com", time.Now().UnixNano())
	dom, err := domainRepo.Create(ctx, repository.DomainCreate{Name: domainName})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	pwHash, _ := auth.HashPassword("irrelevant-mailbox-password")
	mb, err := mailboxRepo.Create(ctx, repository.MailboxCreate{
		DomainID:     dom.ID,
		LocalPart:    "filtered",
		PasswordHash: pwHash,
	})
	if err != nil {
		t.Fatalf("create mailbox: %v", err)
	}
	wantLogin := mb.LocalPart + "@" + domainName

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM dovecot_auth_tokens WHERE target_user = $1`, wantLogin)
		_, _ = pool.Exec(ctx, `DELETE FROM mailboxes WHERE id = $1`, mb.ID)
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, dom.ID)
	})

	// Request carries a super_admin role so canAccessDomain short-circuits to
	// true without an admin_domains row.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxAdminRole, auth.RoleSuperAdmin))

	login, password, revoke, err := srv.getMailboxCredentials(req, mb.ID)
	if err != nil {
		t.Fatalf("getMailboxCredentials: %v", err)
	}
	if revoke == nil {
		t.Fatal("revoke func is nil on success")
	}
	if login != wantLogin {
		t.Errorf("login = %q, want %q (mailbox's own address, not a master user)", login, wantLogin)
	}
	if password == "" {
		t.Error("password is empty, want a minted token password")
	}

	// Exactly one unexpired sieve-purpose token now exists for this mailbox.
	var count int
	var purpose string
	if err := pool.QueryRow(ctx,
		`SELECT count(*), coalesce(max(purpose), '') FROM dovecot_auth_tokens
		 WHERE target_user = $1 AND expires_at > NOW()`, wantLogin,
	).Scan(&count, &purpose); err != nil {
		t.Fatalf("count minted tokens: %v", err)
	}
	if count != 1 {
		t.Errorf("minted token count = %d, want 1", count)
	}
	if purpose != sievePurpose {
		t.Errorf("token purpose = %q, want %q", purpose, sievePurpose)
	}

	// revoke() deletes the token.
	revoke()
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM dovecot_auth_tokens WHERE target_user = $1`, wantLogin,
	).Scan(&count); err != nil {
		t.Fatalf("count after revoke: %v", err)
	}
	if count != 0 {
		t.Errorf("token count after revoke = %d, want 0", count)
	}
}
