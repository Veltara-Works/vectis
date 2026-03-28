//go:build integration

package internal_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/repository"
)

func TestIntegration(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect to Postgres.
	dbCfg := database.Config{
		Host: "127.0.0.1", Port: 5432, Name: "vectis",
		User: "postgres", Password: "vectis_dev_super",
	}
	pool, err := database.NewPool(ctx, dbCfg, logger)
	if err != nil {
		t.Fatalf("connect to postgres: %v", err)
	}
	defer pool.Close()

	// Connect to Valkey.
	vkCfg := database.ValkeyConfig{Host: "127.0.0.1", Port: 6379, Password: "vectis_dev_valkey"}
	vk, err := database.NewValkeyClient(vkCfg, logger)
	if err != nil {
		t.Fatalf("connect to valkey: %v", err)
	}
	defer vk.Close()

	// --- Password hashing ---
	t.Run("argon2id", func(t *testing.T) {
		hash, err := auth.HashPassword("test-password-123")
		if err != nil {
			t.Fatalf("hash password: %v", err)
		}
		ok, err := auth.VerifyPassword("test-password-123", hash)
		if err != nil || !ok {
			t.Fatalf("verify password: ok=%v err=%v", ok, err)
		}
		ok, _ = auth.VerifyPassword("wrong-password", hash)
		if ok {
			t.Fatal("wrong password should not verify")
		}
	})

	// --- Domain CRUD ---
	domainRepo := repository.NewDomainRepo(pool)
	var domainID string

	t.Run("domain_create", func(t *testing.T) {
		d, err := domainRepo.Create(ctx, repository.DomainCreate{Name: "integration-test.com"})
		if err != nil {
			t.Fatalf("create domain: %v", err)
		}
		domainID = d.ID
		if d.Name != "integration-test.com" || !d.Active {
			t.Fatalf("unexpected domain: %+v", d)
		}
	})

	t.Run("domain_get", func(t *testing.T) {
		d, err := domainRepo.GetByName(ctx, "integration-test.com")
		if err != nil || d == nil {
			t.Fatalf("get domain: %v", err)
		}
		if d.ID != domainID {
			t.Fatalf("domain ID mismatch: %s != %s", d.ID, domainID)
		}
	})

	t.Run("domain_list", func(t *testing.T) {
		domains, err := domainRepo.List(ctx, nil)
		if err != nil || len(domains) == 0 {
			t.Fatalf("list domains: %v (count=%d)", err, len(domains))
		}
	})

	// --- Mailbox CRUD ---
	mailboxRepo := repository.NewMailboxRepo(pool)
	var mailboxID string

	t.Run("mailbox_create", func(t *testing.T) {
		hash, _ := auth.HashPassword("mailbox-password")
		m, err := mailboxRepo.Create(ctx, repository.MailboxCreate{
			DomainID:     domainID,
			LocalPart:    "testuser",
			PasswordHash: hash,
		})
		if err != nil {
			t.Fatalf("create mailbox: %v", err)
		}
		mailboxID = m.ID
		if m.LocalPart != "testuser" || m.QuotaMB != 1024 {
			t.Fatalf("unexpected mailbox: %+v", m)
		}
	})

	t.Run("mailbox_get", func(t *testing.T) {
		m, err := mailboxRepo.GetByEmail(ctx, domainID, "testuser")
		if err != nil || m == nil {
			t.Fatalf("get mailbox: %v", err)
		}
		if m.ID != mailboxID {
			t.Fatalf("mailbox ID mismatch")
		}
	})

	// --- Alias CRUD ---
	aliasRepo := repository.NewAliasRepo(pool)

	t.Run("alias_create", func(t *testing.T) {
		a, err := aliasRepo.Create(ctx, repository.AliasCreate{
			DomainID:        domainID,
			SourceLocalPart: "info",
			Destination:     "testuser@integration-test.com",
		})
		if err != nil {
			t.Fatalf("create alias: %v", err)
		}
		if a.SourceLocalPart != "info" {
			t.Fatalf("unexpected alias: %+v", a)
		}
	})

	// --- Admin + Session ---
	adminRepo := repository.NewAdminRepo(pool)
	var adminID string

	t.Run("admin_create", func(t *testing.T) {
		hash, _ := auth.HashPassword("admin-password-123")
		a, err := adminRepo.Create(ctx, repository.AdminCreate{
			Email:        "admin@integration-test.com",
			PasswordHash: hash,
		})
		if err != nil {
			t.Fatalf("create admin: %v", err)
		}
		adminID = a.ID
	})

	t.Run("admin_auth", func(t *testing.T) {
		a, err := adminRepo.GetByEmail(ctx, "admin@integration-test.com")
		if err != nil || a == nil {
			t.Fatalf("get admin: %v", err)
		}
		ok, err := auth.VerifyPassword("admin-password-123", a.PasswordHash)
		if err != nil || !ok {
			t.Fatalf("verify admin password: ok=%v err=%v", ok, err)
		}
	})

	t.Run("session_lifecycle", func(t *testing.T) {
		sm := auth.NewSessionManager(pool, vk, 24, "test-cookie-secret-at-least-32-chars!!")

		token, session, err := sm.CreateSession(ctx, adminID, "127.0.0.1", "test-agent")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		if token == "" || session == nil {
			t.Fatal("empty token or session")
		}

		// Sign and verify token (HMAC).
		signed := sm.SignToken(token)
		extracted, err := sm.VerifyAndExtractToken(signed)
		if err != nil || extracted != token {
			t.Fatalf("sign/verify token: extracted=%s err=%v", extracted, err)
		}

		// Validate session using the raw token.
		gotSessionID, gotAdminID, err := sm.ValidateSession(ctx, token)
		if err != nil || gotAdminID != adminID || gotSessionID != session.ID {
			t.Fatalf("validate session: sessionID=%s adminID=%s err=%v", gotSessionID, gotAdminID, err)
		}

		// List sessions.
		sessions, err := sm.ListSessions(ctx, adminID)
		if err != nil || len(sessions) == 0 {
			t.Fatalf("list sessions: %v", err)
		}

		// Delete session.
		if err := sm.DeleteSession(ctx, session.ID); err != nil {
			t.Fatalf("delete session: %v", err)
		}

		// Should be invalid now.
		_, _, err = sm.ValidateSession(ctx, token)
		if err == nil {
			t.Fatal("deleted session should be invalid")
		}
	})

	// --- Audit log ---
	auditRepo := repository.NewAuditRepo(pool)

	t.Run("audit_log", func(t *testing.T) {
		err := auditRepo.Log(ctx, &adminID, "domain.create", "domain", &domainID,
			map[string]string{"name": "integration-test.com"}, nil)
		if err != nil {
			t.Fatalf("audit log: %v", err)
		}

		entries, err := auditRepo.ListRecent(ctx, 10)
		if err != nil || len(entries) == 0 {
			t.Fatalf("list audit: %v (count=%d)", err, len(entries))
		}
	})

	// --- Cleanup ---
	t.Run("cleanup", func(t *testing.T) {
		sm := auth.NewSessionManager(pool, vk, 24, "test-cookie-secret-at-least-32-chars!!")
		sm.DeleteAllSessions(ctx, adminID)
		adminRepo.Delete(ctx, adminID)
		aliasRepo.Delete(ctx, domainID) // cleanup by domain - won't match but that's OK
		// Delete alias by querying first
		aliases, _ := aliasRepo.ListByDomain(ctx, domainID)
		for _, a := range aliases {
			aliasRepo.Delete(ctx, a.ID)
		}
		mailboxRepo.Delete(ctx, mailboxID)
		domainRepo.Delete(ctx, domainID)
	})
}
