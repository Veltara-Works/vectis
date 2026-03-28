package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/repository"
)

func testData() *TemplateData {
	return &TemplateData{
		Hostname: "mail.example.com",
		TLS:      config.TLSConfig{Provider: "letsencrypt", Email: "admin@example.com"},
		ClamAV:   config.ClamAVConfig{Profile: "none"},
		Rspamd:   config.RspamdConfig{SpamThreshold: 15.0, RejectThreshold: 999, GreylistEnabled: false},
		Postfix:  config.PostfixConfig{MessageSizeLimit: 52428800, SmtpBanner: "$myhostname ESMTP"},
		Dovecot:  config.DovecotConfig{MailLocation: "maildir:/var/vectis/mail/%d/%n/Maildir", QuotaDefaultMB: 1024},
		Logging:  config.LoggingConfig{Level: "info", Driver: "json-file", MaxSizeMB: 50, MaxFiles: 5},
		Admin:    config.AdminConfig{ListenAddr: ":8080", SessionTTLHours: 24},
		Database: config.DatabaseSecrets{Host: "postgres", Port: 5432, Name: "vectis",
			APIUser: "vectis_api", APIPassword: "secret_api",
			PostfixUser: "vectis_postfix", PostfixPassword: "secret_postfix",
			DovecotUser: "vectis_dovecot", DovecotPassword: "secret_dovecot"},
		Valkey: config.ValkeySecrets{Host: "valkey", Port: 6379, Password: "secret_valkey"},
		Domains: []repository.Domain{
			{ID: "d1", Name: "example.com", Active: true, DKIMEnabled: true,
				DKIMSelector: "202603", DKIMKeyPath: strPtr("/var/vectis/dkim/example.com/202603.key"),
				SpamThreshold: 15.0},
		},
	}
}

func strPtr(s string) *string { return &s }

func TestGenerate(t *testing.T) {
	files, err := Generate(testData())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("no files generated")
	}

	// Check expected files exist.
	expected := map[string]bool{
		"postfix/main.cf":                  false,
		"postfix/master.cf":                false,
		"postfix/pgsql_virtual_domains.cf": false,
		"dovecot/dovecot.conf":             false,
		"dovecot/dovecot-sql.conf.ext":     false,
		"rspamd/actions.conf":              false,
		"rspamd/dkim_signing.conf":         false,
		"traefik/traefik.yml":              false,
		"traefik/dynamic.yml":              false,
		"docker-compose.yml":               false,
	}
	for _, f := range files {
		if _, ok := expected[f.RelPath]; ok {
			expected[f.RelPath] = true
		}
	}
	for path, found := range expected {
		if !found {
			t.Errorf("expected file %s not generated", path)
		}
	}
}

func TestPostfixMainCF(t *testing.T) {
	files, _ := Generate(testData())
	var mainCF string
	for _, f := range files {
		if f.RelPath == "postfix/main.cf" {
			mainCF = string(f.Content)
			break
		}
	}
	if mainCF == "" {
		t.Fatal("postfix/main.cf not found")
	}

	checks := []string{
		"myhostname = mail.example.com",
		"virtual_transport = lmtp:inet:dovecot:24",
		"virtual_mailbox_domains = pgsql:/etc/postfix/pgsql_virtual_domains.cf",
		"smtpd_milters = inet:rspamd:11332",
		"message_size_limit = 52428800",
	}
	for _, check := range checks {
		if !strings.Contains(mainCF, check) {
			t.Errorf("main.cf missing: %s", check)
		}
	}
}

func TestDovecotSQL(t *testing.T) {
	files, _ := Generate(testData())
	var sqlConf string
	for _, f := range files {
		if f.RelPath == "dovecot/dovecot-sql.conf.ext" {
			sqlConf = string(f.Content)
			break
		}
	}
	if sqlConf == "" {
		t.Fatal("dovecot-sql.conf.ext not found")
	}

	checks := []string{
		"driver = pgsql",
		"host=postgres",
		"user=vectis_dovecot",
		"password=secret_dovecot",
		"default_pass_scheme = ARGON2ID",
		"userdb_quota_rule",
	}
	for _, check := range checks {
		if !strings.Contains(sqlConf, check) {
			t.Errorf("dovecot-sql.conf.ext missing: %s", check)
		}
	}
}

func TestDKIMSigningConf(t *testing.T) {
	files, _ := Generate(testData())
	var dkimConf string
	for _, f := range files {
		if f.RelPath == "rspamd/dkim_signing.conf" {
			dkimConf = string(f.Content)
			break
		}
	}

	if !strings.Contains(dkimConf, "example.com") {
		t.Error("dkim_signing.conf should contain example.com")
	}
	if !strings.Contains(dkimConf, "202603") {
		t.Error("dkim_signing.conf should contain selector 202603")
	}
}

func TestClamAVNoneOmitsContainer(t *testing.T) {
	files, _ := Generate(testData()) // ClamAV profile is "none"
	var compose string
	for _, f := range files {
		if f.RelPath == "docker-compose.yml" {
			compose = string(f.Content)
			break
		}
	}
	if strings.Contains(compose, "vectis-clamav") {
		t.Error("docker-compose.yml should NOT contain clamav when profile is 'none'")
	}
}

func TestWriteAndDiff(t *testing.T) {
	dir := t.TempDir()
	data := testData()

	// Generate and write.
	files, _ := Generate(data)
	if err := WriteFiles(dir, files); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Verify files exist on disk.
	for _, f := range files {
		path := filepath.Join(dir, f.RelPath)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("file not written: %s", f.RelPath)
		}
	}

	// Diff should show no changes.
	diffs, err := DiffFiles(dir, files)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if len(diffs) != 0 {
		t.Errorf("expected 0 diffs, got %d", len(diffs))
	}

	// Modify a file and check diff.
	mainCFPath := filepath.Join(dir, "postfix/main.cf")
	os.WriteFile(mainCFPath, []byte("modified"), 0644)

	diffs, _ = DiffFiles(dir, files)
	if len(diffs) != 1 || diffs[0].RelPath != "postfix/main.cf" {
		t.Errorf("expected 1 diff for main.cf, got %v", diffs)
	}

	// Delete a file and check diff.
	os.Remove(filepath.Join(dir, "rspamd/actions.conf"))
	diffs, _ = DiffFiles(dir, files)
	found := false
	for _, d := range diffs {
		if d.RelPath == "rspamd/actions.conf" && d.Status == "new" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'new' diff for deleted rspamd/actions.conf")
	}
}

func TestDetermineActions(t *testing.T) {
	tests := []struct {
		name    string
		diffs   []FileDiff
		expect  map[string]string
	}{
		{
			name:   "postfix main.cf → reload",
			diffs:  []FileDiff{{RelPath: "postfix/main.cf", Status: "modified"}},
			expect: map[string]string{"postfix": "reload", "dovecot": "none", "rspamd": "none", "traefik": "none"},
		},
		{
			name:   "postfix master.cf → restart (overrides reload)",
			diffs:  []FileDiff{{RelPath: "postfix/main.cf"}, {RelPath: "postfix/master.cf"}},
			expect: map[string]string{"postfix": "restart"},
		},
		{
			name:   "rspamd actions → reload",
			diffs:  []FileDiff{{RelPath: "rspamd/actions.conf"}},
			expect: map[string]string{"rspamd": "reload"},
		},
		{
			name:   "SQL files → no reload",
			diffs:  []FileDiff{{RelPath: "postfix/pgsql_virtual_domains.cf"}},
			expect: map[string]string{"postfix": "none"},
		},
		{
			name:   "traefik dynamic → none (file watcher)",
			diffs:  []FileDiff{{RelPath: "traefik/dynamic.yml"}},
			expect: map[string]string{"traefik": "none"},
		},
		{
			name:   "traefik static → restart",
			diffs:  []FileDiff{{RelPath: "traefik/traefik.yml"}},
			expect: map[string]string{"traefik": "restart"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actions := DetermineActions(tt.diffs)
			for _, a := range actions {
				if expected, ok := tt.expect[a.Service]; ok {
					if a.Action != expected {
						t.Errorf("%s: expected %s, got %s", a.Service, expected, a.Action)
					}
				}
			}
		})
	}
}
