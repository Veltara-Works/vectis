package mailimport

import "testing"

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
		"<abc@example.com>":     "abc@example.com",
		"  <abc@example.com> ":  "abc@example.com",
		"abc@example.com":       "abc@example.com",
		"<a@b><stray":           "a@b><stray", // only outermost brackets trimmed
		"":                      "",
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
