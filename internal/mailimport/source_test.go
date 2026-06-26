package mailimport

import (
	"net"
	"testing"
)

func TestSourceConfigAddr(t *testing.T) {
	cases := []struct {
		cfg  SourceConfig
		want string
	}{
		{SourceConfig{Host: "mail.example.com", Port: 993, TLS: true}, "mail.example.com:993"},
		{SourceConfig{Host: "mail.example.com", TLS: true}, "mail.example.com:993"},  // default implicit-TLS port
		{SourceConfig{Host: "mail.example.com", TLS: false}, "mail.example.com:143"}, // default STARTTLS port
		{SourceConfig{Host: "mail.example.com", Port: 1993, TLS: true}, "mail.example.com:1993"},
	}
	for _, c := range cases {
		if got := c.cfg.Addr(); got != c.want {
			t.Errorf("Addr(%+v) = %q, want %q", c.cfg, got, c.want)
		}
	}
}

func TestNormalizeMessageID(t *testing.T) {
	cases := map[string]string{
		"<abc@example.com>":    "abc@example.com",
		"  <abc@example.com> ": "abc@example.com",
		"abc@example.com":      "abc@example.com",
		"<a@b><stray":          "a@b><stray", // only outermost brackets trimmed
		"":                     "",
	}
	for in, want := range cases {
		if got := NormalizeMessageID(in); got != want {
			t.Errorf("NormalizeMessageID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFolderIsNoSelect(t *testing.T) {
	if !(Folder{Attrs: []string{`\Noselect`}}).IsNoSelect() {
		t.Error(`\Noselect folder should be IsNoSelect`)
	}
	if !(Folder{Attrs: []string{`\HasChildren`, `\NonExistent`}}).IsNoSelect() {
		t.Error(`\NonExistent folder should be IsNoSelect`)
	}
	if (Folder{Name: "INBOX", Attrs: []string{`\Sent`}}).IsNoSelect() {
		t.Error("selectable folder should not be IsNoSelect")
	}
	if (Folder{Name: "INBOX"}).IsNoSelect() {
		t.Error("attr-less folder should not be IsNoSelect")
	}
}

// TestDisallowedDialTarget locks the SSRF guard's address policy: loopback,
// link-local (incl. cloud metadata 169.254.169.254), private, CGNAT, and
// unspecified addresses must be refused; routable public addresses allowed.
func TestDisallowedDialTarget(t *testing.T) {
	cases := []struct {
		ip   string
		deny bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"169.254.169.254", true}, // cloud metadata
		{"10.0.0.5", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"100.64.0.1", true}, // CGNAT
		{"0.0.0.0", true},
		{"fc00::1", true}, // IPv6 ULA
		{"fe80::1", true}, // IPv6 link-local
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2606:4700:4700::1111", false},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("bad test IP %q", tc.ip)
			}
			if got := disallowedDialTarget(ip); got != tc.deny {
				t.Fatalf("disallowedDialTarget(%s) = %v, want %v", tc.ip, got, tc.deny)
			}
		})
	}
}

// TestSourceConfigValidate checks the static SSRF/port guard.
func TestSourceConfigValidate(t *testing.T) {
	if err := (SourceConfig{Host: "imap.example.com", TLS: true}).validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if err := (SourceConfig{Host: "", TLS: true}).validate(); err == nil {
		t.Fatal("empty host accepted")
	}
	if err := (SourceConfig{Host: "imap.example.com", Port: 6379}).validate(); err == nil {
		t.Fatal("non-IMAP port accepted")
	}
}
