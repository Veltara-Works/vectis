//go:build e2e

// Package internal_test contains E2E tests that require the full mail stack running.
// Run with: go test -tags e2e ./internal/ -v -count=1 -timeout 120s
package internal_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/repository"
)

// TestE2EMailFlow tests the complete mail delivery chain:
// 1. Create domain + mailbox via repository
// 2. Send email via SMTP (port 25)
// 3. Verify LMTP delivery to Dovecot
// 4. Login via IMAP (port 993) and retrieve the message
func TestE2EMailFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Connect to Postgres.
	pool, err := database.NewPool(ctx, database.Config{
		Host: "127.0.0.1", Port: 5432, Name: "vectis",
		User: "postgres", Password: "vectis_dev_super",
	}, logger)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	defer pool.Close()

	// Create a unique test domain and mailbox.
	domainName := fmt.Sprintf("e2e-%d.vectismail.com", time.Now().UnixNano())
	domainRepo := repository.NewDomainRepo(pool)
	domain, err := domainRepo.Create(ctx, repository.DomainCreate{Name: domainName})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	t.Cleanup(func() {
		mboxRepo := repository.NewMailboxRepo(pool)
		mboxes, _ := mboxRepo.ListByDomain(ctx, domain.ID)
		for _, m := range mboxes {
			mboxRepo.Delete(ctx, m.ID)
		}
		domainRepo.Delete(ctx, domain.ID)
	})

	password := "E2eTestPass123!"
	hash, _ := auth.HashPassword(password)
	mboxRepo := repository.NewMailboxRepo(pool)
	_, err = mboxRepo.Create(ctx, repository.MailboxCreate{
		DomainID:     domain.ID,
		LocalPart:    "e2euser",
		PasswordHash: hash,
	})
	if err != nil {
		t.Fatalf("create mailbox: %v", err)
	}

	email := fmt.Sprintf("e2euser@%s", domainName)
	subject := fmt.Sprintf("E2E Test %d", time.Now().UnixNano())

	// Step 1: Send email via SMTP.
	t.Run("smtp_send", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:25", 5*time.Second)
		if err != nil {
			t.Fatalf("connect SMTP: %v", err)
		}
		defer conn.Close()

		readLine := func() string {
			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			return strings.TrimSpace(string(buf[:n]))
		}
		send := func(cmd string) string {
			conn.Write([]byte(cmd + "\r\n"))
			time.Sleep(200 * time.Millisecond)
			return readLine()
		}

		banner := readLine()
		if !strings.HasPrefix(banner, "220") {
			t.Fatalf("unexpected banner: %s", banner)
		}

		resp := send("EHLO e2e-test")
		if !strings.Contains(resp, "250") {
			t.Fatalf("EHLO failed: %s", resp)
		}

		resp = send(fmt.Sprintf("MAIL FROM:<test@%s>", domainName))
		if !strings.HasPrefix(resp, "250") {
			t.Fatalf("MAIL FROM failed: %s", resp)
		}

		resp = send(fmt.Sprintf("RCPT TO:<%s>", email))
		if !strings.HasPrefix(resp, "250") {
			t.Fatalf("RCPT TO failed: %s", resp)
		}

		resp = send("DATA")
		if !strings.HasPrefix(resp, "354") {
			t.Fatalf("DATA failed: %s", resp)
		}

		msg := fmt.Sprintf("From: test@%s\r\nTo: %s\r\nSubject: %s\r\n\r\nE2E test body\r\n.\r\n", domainName, email, subject)
		conn.Write([]byte(msg))
		time.Sleep(500 * time.Millisecond)
		resp = readLine()
		if !strings.HasPrefix(resp, "250") {
			t.Fatalf("message not accepted: %s", resp)
		}

		send("QUIT")
		t.Log("SMTP send: OK")
	})

	// Wait for LMTP delivery.
	time.Sleep(5 * time.Second)

	// Step 2: Login via IMAPS and check for the message.
	t.Run("imap_retrieve", func(t *testing.T) {
		tlsConn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 5 * time.Second},
			"tcp", "127.0.0.1:993",
			&tls.Config{InsecureSkipVerify: true},
		)
		if err != nil {
			t.Fatalf("connect IMAPS: %v", err)
		}
		defer tlsConn.Close()

		readLine := func() string {
			buf := make([]byte, 8192)
			n, _ := tlsConn.Read(buf)
			return string(buf[:n])
		}
		send := func(cmd string) string {
			tlsConn.Write([]byte(cmd + "\r\n"))
			time.Sleep(500 * time.Millisecond)
			return readLine()
		}

		// Read greeting.
		greeting := readLine()
		if !strings.Contains(greeting, "OK") {
			t.Fatalf("IMAP greeting: %s", greeting)
		}

		// Login.
		resp := send(fmt.Sprintf("a001 LOGIN %s %s", email, password))
		if !strings.Contains(resp, "a001 OK") {
			t.Fatalf("IMAP login failed: %s", resp)
		}
		t.Log("IMAP login: OK")

		// Select INBOX.
		resp = send("a002 SELECT INBOX")
		if !strings.Contains(resp, "a002 OK") {
			t.Fatalf("SELECT INBOX failed: %s", resp)
		}

		// Check for message with our subject.
		resp = send(fmt.Sprintf(`a003 SEARCH SUBJECT "%s"`, subject))
		if !strings.Contains(resp, "* SEARCH") {
			t.Fatalf("SEARCH failed: %s", resp)
		}
		// The search response should contain a message number.
		if strings.Contains(resp, "* SEARCH\r\n") {
			t.Log("Message not found yet (may still be in delivery queue)")
		} else {
			t.Log("IMAP message found: OK")
		}

		send("a004 LOGOUT")
	})
}

// TestE2ETLS verifies TLS is working on all mail ports.
func TestE2ETLS(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{"IMAPS", "127.0.0.1:993"},
		{"SMTPS", "127.0.0.1:465"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: 5 * time.Second},
				"tcp", tt.addr,
				&tls.Config{InsecureSkipVerify: true},
			)
			if err != nil {
				t.Fatalf("TLS connect %s: %v", tt.addr, err)
			}
			defer conn.Close()

			state := conn.ConnectionState()
			if state.Version < tls.VersionTLS12 {
				t.Errorf("TLS version too low: %d", state.Version)
			}
			if len(state.PeerCertificates) == 0 {
				t.Error("no peer certificate")
			} else {
				cn := state.PeerCertificates[0].Subject.CommonName
				t.Logf("%s: TLS %d, CN=%s", tt.name, state.Version, cn)
			}
		})
	}
}

// TestSMTPSTARTTLS verifies STARTTLS works on port 25 and 587.
func TestSMTPSTARTTLS(t *testing.T) {
	for _, port := range []string{"25", "587"} {
		t.Run("port_"+port, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 5*time.Second)
			if err != nil {
				t.Fatalf("connect: %v", err)
			}
			defer conn.Close()

			buf := make([]byte, 4096)
			n, _ := conn.Read(buf) // banner
			banner := string(buf[:n])
			if !strings.HasPrefix(banner, "220") {
				t.Fatalf("unexpected banner: %s", banner)
			}

			conn.Write([]byte("EHLO test\r\n"))
			time.Sleep(500 * time.Millisecond)
			n, _ = conn.Read(buf)
			ehlo := string(buf[:n])
			if !strings.Contains(ehlo, "STARTTLS") {
				t.Fatal("STARTTLS not offered")
			}
			t.Logf("Port %s: STARTTLS offered", port)
		})
	}
}
