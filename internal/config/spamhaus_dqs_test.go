package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRspamdSecretsDQSKey(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"},
		{"ABCDEFGHIJ0123456789klmnop", "abcdefghij0123456789klmnop"}, // lowercased for DNS
		{"tooshort", ""},
		{"abcdefghijklmnop.evil.example", ""},    // would add DNS labels
		{"abcdefghijklmnop\";\n  rbl = \"x", ""}, // would break out of the rspamd string
		{"abcdefghijklmnop qrstuvwxyz", ""},      // whitespace
		{strings.Repeat("a", 64), ""},            // longer than one DNS label
	}
	for _, c := range cases {
		if got := (RspamdSecrets{SpamhausDQSKey: c.in}).DQSKey(); got != c.want {
			t.Errorf("DQSKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidateSecretsSpamhausDQSKey(t *testing.T) {
	base := func() *VectisSecrets {
		var s VectisSecrets
		s.Database = DatabaseSecrets{Name: "vectis", SuperuserPassword: "x", APIPassword: "x", PostfixPassword: "x", DovecotPassword: "x"}
		s.Valkey.Password = "x"
		s.API = APISecrets{Secret: strings.Repeat("s", 32), AdminEmail: "a@example.com", AdminPassword: "longenough", BackupEncryptionKey: "k"}
		s.Orchestrator.Token = "t"
		return &s
	}
	hasField := func(list []ValidationError) bool {
		for _, e := range list {
			if e.Field == "rspamd.spamhaus_dqs_key" {
				return true
			}
		}
		return false
	}

	s := base()
	r := ValidateSecrets(s)
	if hasField(r.Errors) {
		t.Error("an absent key must be valid (it is optional)")
	}
	if !hasField(r.Warnings) {
		t.Error("an absent key must produce the bring-your-own-key warning")
	}
	s.Rspamd.SpamhausDQSKey = "abcdefghijklmnopqrstuvwxyz"
	if r := ValidateSecrets(s); hasField(r.Errors) || hasField(r.Warnings) {
		t.Error("a well-formed key must be valid and silence the warning")
	}
	s.Rspamd.SpamhausDQSKey = "not a key"
	if !hasField(ValidateSecrets(s).Errors) {
		t.Error("a malformed key must be reported")
	}
}

// The rspamd block decodes from secrets.yaml, and an unknown sibling field is
// tolerated (Forward), like the other optional secrets sections.
func TestRspamdSecretsYAML(t *testing.T) {
	var s VectisSecrets
	in := "rspamd:\n  spamhaus_dqs_key: abcdefghijklmnopqrstuvwxyz\n  future_field: 1\n"
	dec := yaml.NewDecoder(strings.NewReader(in))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if s.Rspamd.DQSKey() != "abcdefghijklmnopqrstuvwxyz" {
		t.Fatalf("key = %q", s.Rspamd.SpamhausDQSKey)
	}
}
