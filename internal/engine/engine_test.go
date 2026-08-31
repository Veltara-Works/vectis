package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/repository"
)

func testData() *TemplateData {
	return &TemplateData{
		Hostname:  "mail.example.com",
		TLS:       config.TLSConfig{Provider: "letsencrypt", Email: "admin@example.com"},
		Resources: resolveResourceKnobs("small"),
		ClamAV:    resolveClamAVKnobs("none"),
		Rspamd:    config.RspamdConfig{SpamThreshold: 15.0, RejectThreshold: 999, GreylistEnabled: false},
		Postfix:   config.PostfixConfig{MessageSizeLimit: 52428800, SmtpBanner: "$myhostname ESMTP"},
		Dovecot:   config.DovecotConfig{MailLocation: "maildir:/var/vectis/mail/%d/%n/Maildir", QuotaDefaultMB: 1024},
		Logging:   config.LoggingConfig{Level: "info", Driver: "json-file", MaxSizeMB: 50, MaxFiles: 5},
		Admin:     config.AdminConfig{ListenAddr: ":8080", SessionTTLHours: 24},
		Database: config.DatabaseSecrets{Host: "postgres", Port: 5432, Name: "vectis",
			SuperuserPassword: "secret_super",
			APIUser:           "vectis_api", APIPassword: "secret_api",
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
	//
	// Note: webmail skin (meta.json + styles.css) is no longer engine-rendered
	// — it's baked into the vectis-webmail Docker image at /usr/src/roundcubemail/skins/vectis/.
	// See docs/notes/deferred-items.md §13 closure for the rationale.
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
		"webmail/roundcube.config.php":     false,
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
		"smtputf8_enable = no",
		"virtual_mailbox_domains = pgsql:/etc/postfix/pgsql_virtual_domains.cf",
		"smtpd_milters = inet:rspamd:11332",
		"message_size_limit = 52428800",
		// Virtual-only: alias_maps/alias_database cleared so Postfix doesn't open
		// the never-built default lmdb:/etc/postfix/aliases (log-noise on smtpd start).
		// Anchored with newlines so they match the exact empty-value lines and not
		// the "virtual_alias_maps = pgsql:..." line above.
		"\nalias_maps =\n",
		"\nalias_database =\n",
		// TLS session cache on lmdb, not btree — the Alpine image has no Berkeley DB.
		"smtpd_tls_session_cache_database = lmdb:",
		"smtp_tls_session_cache_database = lmdb:",
	}
	for _, check := range checks {
		if !strings.Contains(mainCF, check) {
			t.Errorf("main.cf missing: %s", check)
		}
	}
	// Guard against a btree: TLS cache regressing (unavailable on Alpine postfix).
	// Directive-specific so an explanatory comment mentioning btree can't trip it.
	if strings.Contains(mainCF, "session_cache_database = btree:") {
		t.Errorf("main.cf uses btree: TLS cache (no Berkeley DB in the Alpine image) — use lmdb:")
	}
}

// TestPostfixMasterCFSubmissionPolicy verifies the submission/smtps services
// call the Vectis send-suspend policy server (vectis-private #5). Without this
// the per-mailbox suspend + abuse auto-suspend are enforced only on the HTTP
// send API and bypassable via authenticated SMTP submission.
func TestPostfixMasterCFSubmissionPolicy(t *testing.T) {
	files, _ := Generate(testData())
	var masterCF string
	for _, f := range files {
		if f.RelPath == "postfix/master.cf" {
			masterCF = string(f.Content)
			break
		}
	}
	if masterCF == "" {
		t.Fatal("postfix/master.cf not found")
	}

	// The restriction-class reference must appear exactly twice — once for
	// submission (587), once for smtps (465) — and never leak onto inbound :25.
	// A class (single token) is used because a master.cf -o value cannot contain
	// whitespace; the class itself is defined in main.cf.
	const policyHook = "-o smtpd_data_restrictions=vectis_submission_policy"
	if n := strings.Count(masterCF, policyHook); n != 2 {
		t.Errorf("policy hook count = %d, want 2 (submission + smtps)\n%s", n, masterCF)
	}
	if n := strings.Count(masterCF, "-o smtpd_policy_service_default_action=DUNNO"); n != 2 {
		t.Errorf("policy default_action override count = %d, want 2", n)
	}
	// The master.cf -o value must remain a single whitespace-free token, else
	// Postfix splits it into a stray argument.
	if strings.Contains(masterCF, "smtpd_data_restrictions=check_policy_service") {
		t.Error("master.cf inlines check_policy_service with a space — will be split by Postfix; use the restriction class")
	}
}

// TestPostfixMainCFSubmissionPolicyClass verifies the restriction class the
// submission services reference is actually defined in main.cf and points at the
// policy server.
func TestPostfixMainCFSubmissionPolicyClass(t *testing.T) {
	files, _ := Generate(testData())
	var mainCF string
	for _, f := range files {
		if f.RelPath == "postfix/main.cf" {
			mainCF = string(f.Content)
			break
		}
	}
	checks := []string{
		"smtpd_restriction_classes = vectis_submission_policy",
		"vectis_submission_policy = check_policy_service inet:vectis-api:10099",
	}
	for _, c := range checks {
		if !strings.Contains(mainCF, c) {
			t.Errorf("main.cf missing policy class line: %s", c)
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

	// Dovecot 2.4 inline SQL form: named pgsql{} connection filter + passdb/userdb
	// sql{} blocks, %{user} variables, and the quota_storage_size userdb field.
	checks := []string{
		"sql_driver = pgsql",
		"pgsql main {",
		"host = postgres",
		"user = vectis_dovecot",
		"password = secret_dovecot",
		"passdb sql {",
		"default_password_scheme = ARGON2ID",
		"userdb sql {",
		"quota_storage_size",
		"'%{user}'",
	}
	for _, check := range checks {
		if !strings.Contains(sqlConf, check) {
			t.Errorf("dovecot-sql.conf.ext missing: %s", check)
		}
	}
}

// TestDovecotAuthTokenPassdb verifies the server-side auth-token passdb (used by
// the native IMAP importer / impersonation) is wired BEFORE the mailbox passdb
// and is fail-safe — it must never be able to break normal mailbox auth.
func TestDovecotAuthTokenPassdb(t *testing.T) {
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

	tokenQuery := "FROM dovecot_auth_tokens WHERE target_user = '%{user}' AND expires_at > NOW()"
	mailboxQuery := "FROM mailboxes m JOIN domains d"

	tokenIdx := strings.Index(sqlConf, tokenQuery)
	mailboxIdx := strings.Index(sqlConf, mailboxQuery)
	if tokenIdx < 0 {
		t.Fatal("token passdb query not found")
	}
	if mailboxIdx < 0 {
		t.Fatal("mailbox passdb query not found")
	}
	// The token passdb MUST precede the mailbox passdb (so a token can win, while
	// absent tokens fall through to real auth).
	if tokenIdx > mailboxIdx {
		t.Error("token passdb must be listed before the mailbox passdb")
	}

	// CRITICAL (Dovecot 2.4 named-filter semantics, validated on a live 2.4.3
	// harness): the token passdb is a SECOND sql passdb and must carry a DISTINCT
	// filter name. Two unnamed `passdb sql {}` blocks silently collapse into one —
	// the token passdb becomes inert and token auth never runs. Guard against any
	// regression to twin-unnamed blocks.
	// Anchor on line-start ("\n") so explanatory comment prose mentioning these
	// tokens (e.g. "two unnamed `passdb sql {}`") is not counted as a real block.
	if !strings.Contains(sqlConf, "\npassdb auth_token {") {
		t.Error("token passdb must use a distinct filter name (passdb auth_token {); " +
			"a second unnamed `passdb sql {}` collapses into the mailbox passdb and goes inert")
	}
	if n := strings.Count(sqlConf, "\npassdb sql {"); n != 1 {
		t.Errorf("expected exactly one unnamed `passdb sql {` block (the mailbox passdb); "+
			"two would collapse — got %d", n)
	}
	// The token block selects the sql driver explicitly (required once the filter
	// name is not literally `sql`).
	if !strings.Contains(sqlConf, "\npassdb auth_token {\n    driver = sql") {
		t.Error("token passdb (auth_token) must set `driver = sql` explicitly")
	}
	// Fail-safe settings — without these a token miss or DB error would break
	// normal auth. With a custom filter name they must be fully-qualified.
	for _, must := range []string{"passdb_result_failure = continue", "passdb_result_internalfail = continue"} {
		if !strings.Contains(sqlConf, must) {
			t.Errorf("token passdb missing fail-safe setting: %s", must)
		}
	}
}

// TestDovecotMailLocation verifies the 2.4 mail_location → mail_driver/mail_path/
// mail_home split (a key migration risk): the combined mail_location is gone and
// the maildir path is rendered with the 2.4 %{user | ...} expansion syntax derived
// from .Dovecot.MailLocation (testData sets "maildir:/var/vectis/mail/%d/%n/Maildir").
func TestDovecotMailLocation(t *testing.T) {
	files, _ := Generate(testData())
	var dc string
	for _, f := range files {
		if f.RelPath == "dovecot/dovecot.conf" {
			dc = string(f.Content)
			break
		}
	}
	if dc == "" {
		t.Fatal("dovecot.conf not found")
	}

	// The combined 2.3 setting must be gone (silently ignored by 2.4 -> no
	// delivery). Match the directive form ("mail_location =") so the explanatory
	// comment that mentions the word doesn't trip the assertion.
	if strings.Contains(dc, "mail_location =") {
		t.Error("dovecot.conf still contains the legacy mail_location setting")
	}
	want := []string{
		"mail_driver = maildir",
		"mail_path = /var/vectis/mail/%{user | domain}/%{user | username}/Maildir",
		"mail_home = /var/vectis/mail/%{user | domain}/%{user | username}",
	}
	for _, w := range want {
		if !strings.Contains(dc, w) {
			t.Errorf("dovecot.conf missing 2.4 mail setting: %q", w)
		}
	}
	// No legacy one-letter variables should survive the conversion.
	for _, bad := range []string{"%d/", "/%n/", "%u"} {
		if strings.Contains(dc, bad) {
			t.Errorf("dovecot.conf still contains legacy 2.3 variable %q (should be %%{user | ...})", bad)
		}
	}
}

// TestAdvancedSpamConfig verifies the Pro per-domain advanced spam pipeline
// (settings.conf overrides + Lua extension + four allow/block map files)
// renders end-to-end from TemplateData. Empty-state coverage lives in
// TestAdvancedSpamConfig_EmptyEntriesProducesEmptyMaps below.
func TestAdvancedSpamConfig(t *testing.T) {
	data := testData()
	greylistOff := false
	rejectAt := 12.5
	data.Domains[0].RejectThreshold = &rejectAt
	data.Domains[0].GreylistEnabled = &greylistOff
	data.SpamListEntries = []SpamListInfo{
		{DomainName: "example.com", Kind: "block", Scope: "domain", Pattern: "spam.example"},
		{DomainName: "example.com", Kind: "block", Scope: "email", Pattern: "phisher@evil.example"},
		{DomainName: "example.com", Kind: "allow", Scope: "domain", Pattern: "trusted.example"},
		{DomainName: "example.com", Kind: "allow", Scope: "email", Pattern: "vip@partner.example"},
	}

	files, err := Generate(data)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	want := map[string]string{
		"rspamd/settings.conf":         "domain_example.com",
		"rspamd/rspamd.local.lua":      "VECTIS_SPAM_LISTS",
		"rspamd/maps/block_domain.map": "example.com:spam.example",
		"rspamd/maps/block_email.map":  "example.com:phisher@evil.example",
		"rspamd/maps/allow_domain.map": "example.com:trusted.example",
		"rspamd/maps/allow_email.map":  "example.com:vip@partner.example",
	}
	for path, mustContain := range want {
		var content string
		for _, f := range files {
			if f.RelPath == path {
				content = string(f.Content)
				break
			}
		}
		if content == "" {
			t.Errorf("%s not generated", path)
			continue
		}
		if !strings.Contains(content, mustContain) {
			t.Errorf("%s missing %q; got:\n%s", path, mustContain, content)
		}
	}

	// The settings.conf must apply BOTH overrides (reject + disable greylist)
	// for the example.com domain block.
	var settings string
	for _, f := range files {
		if f.RelPath == "rspamd/settings.conf" {
			settings = string(f.Content)
			break
		}
	}
	if !strings.Contains(settings, "reject = 12.5") {
		t.Errorf("settings.conf should override reject threshold to 12.5; got:\n%s", settings)
	}
	if !strings.Contains(settings, `plugins_disabled = ["greylist"]`) {
		t.Errorf("settings.conf should disable greylist plugin when GreylistEnabled=false; got:\n%s", settings)
	}
}

// TestAdvancedSpamConfig_EmptyEntriesProducesEmptyMaps locks in the
// invariant that the four map files always render — even on Free with no
// entries — so the docker-compose bind mounts are always valid. Without
// this, a fresh install would have a missing /var/vectis/generated/rspamd/
// maps/*.map source and rspamd would refuse to start.
func TestAdvancedSpamConfig_EmptyEntriesProducesEmptyMaps(t *testing.T) {
	data := testData()
	data.SpamListEntries = nil // explicit empty / Free tier

	files, err := Generate(data)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	required := []string{
		"rspamd/settings.conf",
		"rspamd/rspamd.local.lua",
		"rspamd/maps/allow_email.map",
		"rspamd/maps/allow_domain.map",
		"rspamd/maps/block_email.map",
		"rspamd/maps/block_domain.map",
	}
	got := make(map[string]bool, len(required))
	for _, f := range files {
		got[f.RelPath] = true
	}
	for _, p := range required {
		if !got[p] {
			t.Errorf("missing %s in empty-entries render", p)
		}
	}
}

// TestAdvancedSpamLua_LookupUsesEqTrue locks the membership check at
// `== true`. rspamd's `set` map type returns boolean (true / false), not
// (something / nil) — using `~= nil` matches every key (false ~= nil is
// true) and the prefilter rejects every message regardless of map content.
// Caught live on rspamd 3.10.2 during v0.1.1 → v0.1.2 fix walk.
func TestAdvancedSpamLua_LookupUsesEqTrue(t *testing.T) {
	data := testData()
	data.SpamListEntries = nil
	files, err := Generate(data)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var lua string
	for _, f := range files {
		if f.RelPath == "rspamd/rspamd.local.lua" {
			lua = string(f.Content)
			break
		}
	}
	if lua == "" {
		t.Fatal("rspamd.local.lua not generated")
	}
	if !strings.Contains(lua, "== true") {
		t.Errorf("rspamd.local.lua must check `== true` (set map returns false on miss, not nil); got:\n%s", lua)
	}
	if strings.Contains(lua, "~= nil") {
		t.Errorf("rspamd.local.lua must NOT use `~= nil` for set membership — false ~= nil is true and matches every key")
	}
}

// The inbound-notify pipe must skip spam-flagged mail by default, and must key
// on rspamd's X-Spam header rather than re-deriving a score threshold locally —
// otherwise the threshold lives in two places and drifts.
func TestInboundNotify_SkipsSpamByDefault(t *testing.T) {
	data := testData()
	files, err := Generate(data)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var sh string
	for _, f := range files {
		if strings.HasSuffix(f.RelPath, "inbound-notify.sh") {
			sh = string(f.Content)
			break
		}
	}
	if sh == "" {
		t.Fatal("inbound-notify.sh not generated")
	}
	if !strings.Contains(sh, "X-Spam:") {
		t.Fatal("notify pipe does not gate on the X-Spam flag — every phish to a role address raises a notification")
	}
	// Must not duplicate the threshold: the score lives in rspamd.spam_threshold.
	if strings.Contains(sh, "SPAM_SCORE -gt") || strings.Contains(sh, "SPAM_SCORE >") {
		t.Error("notify pipe must not re-implement a score threshold; gate on the X-Spam header rspamd sets")
	}
	// The gate must exit BEFORE the payload is built and POSTed.
	gate := strings.Index(sh, "X-Spam:")
	post := strings.Index(sh, "PAYLOAD_FILE")
	if gate < 0 || post < 0 || gate > strings.LastIndex(sh, "API_URL") && gate > post {
		t.Error("spam gate must run before the payload is assembled and posted")
	}
}

// Opting out must remove the gate entirely, not merely invert it.
func TestInboundNotify_SkipSpamCanBeDisabled(t *testing.T) {
	data := testData()
	off := false
	data.Postfix.InboundNotifySkipSpam = &off
	files, err := Generate(data)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f.RelPath, "inbound-notify.sh") {
			if strings.Contains(string(f.Content), "skipping inbound POST for spam-flagged") {
				t.Error("inbound_notify_skip_spam=false must not emit the spam gate")
			}
			return
		}
	}
	t.Fatal("inbound-notify.sh not generated")
}

// TestAdvancedSpamCompose_APIBindMount locks in the api → host bind mount
// for /var/vectis/generated/rspamd. Without this, regenerateRspamdSpamConfig
// writes the spam maps to the api container's overlay filesystem; rspamd
// (which reads from the host path) never sees them and the feature silently
// no-ops on every install. Caught on sysadmin1001 during v0.1.1 E2E.
func TestAdvancedSpamCompose_APIBindMount(t *testing.T) {
	files, _ := Generate(testData())
	var compose string
	for _, f := range files {
		if f.RelPath == "docker-compose.yml" {
			compose = string(f.Content)
			break
		}
	}
	if compose == "" {
		t.Fatal("docker-compose.yml not generated")
	}
	apiBlock := serviceBlock(compose, "api")
	if apiBlock == "" {
		t.Fatal("api service block not found in compose")
	}
	if !strings.Contains(apiBlock, "/var/vectis/generated/rspamd:/var/vectis/generated/rspamd") {
		t.Errorf("api service must bind-mount /var/vectis/generated/rspamd so spam-list regen reaches rspamd; got:\n%s", apiBlock)
	}
}

// The api service must persist /var/vectis/backups on the host. Without this
// bind, backups land on the container's ephemeral layer and are destroyed by
// every cutover's compose down/up — there is no durable backup at all. Caught
// by the 2026-05-30 DR drill (finding F1); see docs/notes/dr-drill-2026-05-30.md.
func TestBackupsCompose_APIBindMount(t *testing.T) {
	files, _ := Generate(testData())
	var compose string
	for _, f := range files {
		if f.RelPath == "docker-compose.yml" {
			compose = string(f.Content)
			break
		}
	}
	if compose == "" {
		t.Fatal("docker-compose.yml not generated")
	}
	apiBlock := serviceBlock(compose, "api")
	if apiBlock == "" {
		t.Fatal("api service block not found in compose")
	}
	if !strings.Contains(apiBlock, "/var/vectis/backups:/var/vectis/backups") {
		t.Errorf("api service must bind-mount /var/vectis/backups so backups survive container recreate; got:\n%s", apiBlock)
	}
}

// The api service must persist /var/vectis/license on the host so the offline
// license verifier's JWKS write-through cache survives container recreate.
// /var/vectis is NOT mounted as a whole — only specific subpaths — so without
// this dedicated bind the cache lands on the ephemeral layer and the
// resolver's cache layer is dead. See DefaultJWKSCachePath in
// internal/config/schema.go (Copilot review, PR #96).
func TestLicenseCacheCompose_APIBindMount(t *testing.T) {
	files, _ := Generate(testData())
	var compose string
	for _, f := range files {
		if f.RelPath == "docker-compose.yml" {
			compose = string(f.Content)
			break
		}
	}
	if compose == "" {
		t.Fatal("docker-compose.yml not generated")
	}
	apiBlock := serviceBlock(compose, "api")
	if apiBlock == "" {
		t.Fatal("api service block not found in compose")
	}
	if !strings.Contains(apiBlock, "/var/vectis/license:/var/vectis/license") {
		t.Errorf("api service must bind-mount /var/vectis/license so the JWKS cache survives container recreate; got:\n%s", apiBlock)
	}
}

// serviceBlock returns the compose service block for `name`, ending at the
// next top-level `  <name>:` line (or end of file). A service header is
// exactly `  ` + word + `:` at the start of a line; continuation lines for
// the current service all have at least 4 leading spaces or are blank.
func serviceBlock(compose, name string) string {
	header := "\n  " + name + ":\n"
	start := strings.Index(compose, header)
	if start < 0 {
		return ""
	}
	rest := compose[start+1:]
	lines := strings.SplitAfter(rest, "\n")
	var b strings.Builder
	for i, ln := range lines {
		trimmed := strings.TrimRight(ln, "\n")
		if i > 0 &&
			strings.HasPrefix(trimmed, "  ") &&
			!strings.HasPrefix(trimmed, "   ") &&
			strings.HasSuffix(trimmed, ":") {
			break
		}
		b.WriteString(ln)
	}
	return b.String()
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

func TestPostgresBootstrap(t *testing.T) {
	files, _ := Generate(testData())

	var compose string
	for _, f := range files {
		if f.RelPath == "docker-compose.yml" {
			compose = string(f.Content)
			break
		}
	}
	if compose == "" {
		t.Fatal("docker-compose.yml not generated")
	}

	checks := []string{
		`POSTGRES_USER: postgres`,
		`POSTGRES_PASSWORD: "secret_super"`,
		`POSTGRES_DB: "vectis"`,
		`VECTIS_API_PASSWORD: "secret_api"`,
		`/var/vectis/generated/postgres/init-users.sh:/docker-entrypoint-initdb.d/01-init-users.sh:ro`,
		// Healthcheck must hit TCP — see template comment. Port publishing
		// was removed: vectis-data is internal: true and Docker silently
		// drops `ports:` on internal networks, so host-side connections
		// were never viable. Bootstrap work runs in-container instead.
		`pg_isready -h 127.0.0.1`,
	}

	// Postgres must not expose a published port on any host interface —
	// doing so would be a silent no-op today (vectis-data is internal)
	// and a security regression the day we lift that constraint.
	if strings.Contains(compose, `127.0.0.1:5432:5432`) {
		t.Error("postgres should not publish 5432 on the host; run bootstrap via docker compose run")
	}
	for _, c := range checks {
		if !strings.Contains(compose, c) {
			t.Errorf("docker-compose.yml missing postgres bootstrap line: %s", c)
		}
	}

	// init-users.sh must be rendered with executable mode so the postgres
	// uid inside the container can read+exec it from the host bind-mount.
	var initScript *GeneratedFile
	for i := range files {
		if files[i].RelPath == "postgres/init-users.sh" {
			initScript = &files[i]
			break
		}
	}
	if initScript == nil {
		t.Fatal("postgres/init-users.sh not generated")
	}
	if initScript.Mode != 0755 {
		t.Errorf("postgres/init-users.sh: expected mode 0755, got %o", initScript.Mode)
	}
	if !strings.Contains(string(initScript.Content), "CREATE ROLE vectis_api") {
		t.Error("init-users.sh missing CREATE ROLE vectis_api")
	}
}

// TestGeneratedConfigsAreBindMounted catches the rc12 regression where
// traefik / postfix / dovecot / rspamd were mounted as empty named volumes
// and silently ran their image-default configs. The generated files live
// on the host under /var/vectis/generated/<service>/ and MUST be
// bind-mounted into the container paths expected by each daemon.
func TestGeneratedConfigsAreBindMounted(t *testing.T) {
	files, _ := Generate(testData())
	var compose string
	for _, f := range files {
		if f.RelPath == "docker-compose.yml" {
			compose = string(f.Content)
		}
	}

	requiredMounts := []string{
		// Traefik — without these, no routers match and the admin UI 404s.
		`/var/vectis/generated/traefik/traefik.yml:/etc/traefik/traefik.yml:ro`,
		`/var/vectis/generated/traefik/dynamic.yml:/etc/traefik/dynamic/dynamic.yml:ro`,
		// Postfix core configs.
		`/var/vectis/generated/postfix/main.cf:/etc/postfix/main.cf:ro`,
		`/var/vectis/generated/postfix/master.cf:/etc/postfix/master.cf:ro`,
		`/var/vectis/generated/postfix/pgsql_virtual_domains.cf:/etc/postfix/pgsql_virtual_domains.cf:ro`,
		`/var/vectis/generated/postfix/inbound-notify.sh:/etc/postfix/inbound-notify.sh:ro`,
		// Dovecot auth + SQL lookup.
		`/var/vectis/generated/dovecot/dovecot.conf:/etc/dovecot/dovecot.conf:ro`,
		`/var/vectis/generated/dovecot/dovecot-sql.conf.ext:/etc/dovecot/dovecot-sql.conf.ext:ro`,
		// Dovecot global spam->Junk sieve (always mounted; see TestSpamToJunk*).
		`/var/vectis/generated/dovecot/spam-to-junk.sieve:/etc/dovecot/sieve/spam-to-junk.sieve:ro`,
		// Rspamd scoring + DKIM signing.
		`/var/vectis/generated/rspamd/dkim_signing.conf:/etc/rspamd/local.d/dkim_signing.conf:ro`,
		`/var/vectis/generated/rspamd/milter_headers.conf:/etc/rspamd/local.d/milter_headers.conf:ro`,
		// DKIM keys MUST be a host bind mount (not a named volume) so keys
		// written by the host CLI `vectis domain add` are visible to rspamd.
		`/var/vectis/dkim:/var/vectis/dkim:ro`,
	}
	for _, m := range requiredMounts {
		if !strings.Contains(compose, m) {
			t.Errorf("generated compose is missing required bind mount: %s", m)
		}
	}

	forbiddenMounts := []string{
		`traefik-config:/etc/traefik`,
		`postfix-config:/etc/postfix`,
		`dovecot-config:/etc/dovecot`,
		`rspamd-config:/etc/rspamd/local.d`,
	}
	for _, m := range forbiddenMounts {
		if strings.Contains(compose, m) {
			t.Errorf("compose still has named-volume config mount: %s (must be a bind mount from /var/vectis/generated)", m)
		}
	}
}

// TestOrchestratorEtcVectisMountIsRW locks in the rc35 fix: the orchestrator
// container needs WRITE access to /etc/vectis so Phase 3.5 of Apply can rewrite
// docker-compose.yml with target image tags (atomic tmp-file-then-rename, which
// requires write perm on the directory). Pre-rc35 both api and orchestrator had
// :ro — Phase 3.5 failed with "read-only file system" and the follow-up
// rollback failed identically. Caught during the 2026-04-24 sysadmin1001
// walkthrough. The api service keeps :ro (it only reads config).
func TestOrchestratorEtcVectisMountIsRW(t *testing.T) {
	files, _ := Generate(testData())
	var compose string
	for _, f := range files {
		if f.RelPath == "docker-compose.yml" {
			compose = string(f.Content)
			break
		}
	}
	if compose == "" {
		t.Fatal("docker-compose.yml not generated")
	}

	// Crudely extract the orchestrator service block: from "  orchestrator:"
	// through the next top-level (2-space-indented) service.
	orchIdx := strings.Index(compose, "\n  orchestrator:\n")
	if orchIdx == -1 {
		t.Fatal("orchestrator service block not found in compose")
	}
	// Advance past the "\n  orchestrator:\n" label and look for the next "\n  <name>:\n".
	rest := compose[orchIdx+len("\n  orchestrator:\n"):]
	end := len(rest)
	for i := 0; i < len(rest)-4; i++ {
		if rest[i] == '\n' && rest[i+1] == ' ' && rest[i+2] == ' ' && rest[i+3] != ' ' && rest[i+3] != '-' && rest[i+3] != '#' {
			end = i
			break
		}
	}
	orchBlock := rest[:end]

	if !strings.Contains(orchBlock, "/etc/vectis:/etc/vectis") {
		t.Fatal("orchestrator block missing /etc/vectis mount entirely")
	}
	if strings.Contains(orchBlock, "/etc/vectis:/etc/vectis:ro") {
		t.Error("orchestrator /etc/vectis mount is :ro — Phase 3.5 compose rewrite cannot write its tmp file; remove :ro from the orchestrator volume in docker-compose.yml.tmpl")
	}

	// api keeps :ro — it only reads config, doesn't write.
	apiIdx := strings.Index(compose, "\n  api:\n")
	if apiIdx == -1 {
		t.Fatal("api service block not found in compose")
	}
	apiRest := compose[apiIdx+len("\n  api:\n"):]
	apiEnd := len(apiRest)
	for i := 0; i < len(apiRest)-4; i++ {
		if apiRest[i] == '\n' && apiRest[i+1] == ' ' && apiRest[i+2] == ' ' && apiRest[i+3] != ' ' && apiRest[i+3] != '-' && apiRest[i+3] != '#' {
			apiEnd = i
			break
		}
	}
	apiBlock := apiRest[:apiEnd]
	if !strings.Contains(apiBlock, "/etc/vectis:/etc/vectis:ro") {
		t.Error("api /etc/vectis mount lost :ro — api reads config only; only orchestrator needs RW")
	}
}

// TestOrchestratorPortBoundToLocalhost locks in the 2026-05-08 fix: the
// orchestrator must publish 8081 to 127.0.0.1 so the host-side
// `vectis update {plan,apply}` CLI can reach its default localhost:8081
// without an env-var workaround. Bound to 127.0.0.1 only — never expose
// the orchestrator API publicly. Surfaced during the sa1001 walkthrough
// when the CLI failed with "connection refused" on a prod-shaped install
// because compose had no host-side port binding for orchestrator.
func TestOrchestratorPortBoundToLocalhost(t *testing.T) {
	files, _ := Generate(testData())
	var compose string
	for _, f := range files {
		if f.RelPath == "docker-compose.yml" {
			compose = string(f.Content)
			break
		}
	}
	if compose == "" {
		t.Fatal("docker-compose.yml not generated")
	}

	orchIdx := strings.Index(compose, "\n  orchestrator:\n")
	if orchIdx == -1 {
		t.Fatal("orchestrator service block not found in compose")
	}
	rest := compose[orchIdx+len("\n  orchestrator:\n"):]
	end := len(rest)
	for i := 0; i < len(rest)-4; i++ {
		if rest[i] == '\n' && rest[i+1] == ' ' && rest[i+2] == ' ' && rest[i+3] != ' ' && rest[i+3] != '-' && rest[i+3] != '#' {
			end = i
			break
		}
	}
	orchBlock := rest[:end]

	if !strings.Contains(orchBlock, "127.0.0.1:8081:8081") {
		t.Error("orchestrator block missing localhost-bound port 8081 — `vectis update plan/apply` CLI will fail with 'connection refused' on prod-shaped installs")
	}
	// Defensive: the binding must be localhost-only, never a bare 8081:8081
	// (which would expose orchestrator API publicly on every interface).
	if strings.Contains(orchBlock, "\n      - \"8081:8081\"") || strings.Contains(orchBlock, "\n      - 8081:8081\n") {
		t.Error("orchestrator port 8081 is bound to all interfaces — must be 127.0.0.1:8081:8081 to avoid exposing the orchestrator API publicly")
	}
}

// TestOrchestratorMountsGeneratedConfigDir locks in the v0.1.6 fix: the
// orchestrator container needs a /var/vectis/generated bind mount so
// RegenerateConfigs (called by self-heal on cross-version startup) can
// write per-service config files. Pre-v0.1.5 templates omitted this mount
// entirely; legacy installs hit "no such file or directory" on every
// boot's reconcile attempt. See feedback_v0.1.5_selfheal_legacy_install_broken.md.
func TestOrchestratorMountsGeneratedConfigDir(t *testing.T) {
	files, _ := Generate(testData())
	var compose string
	for _, f := range files {
		if f.RelPath == "docker-compose.yml" {
			compose = string(f.Content)
			break
		}
	}
	if compose == "" {
		t.Fatal("docker-compose.yml not generated")
	}

	orchIdx := strings.Index(compose, "\n  orchestrator:\n")
	if orchIdx == -1 {
		t.Fatal("orchestrator service block not found in compose")
	}
	rest := compose[orchIdx+len("\n  orchestrator:\n"):]
	end := len(rest)
	for i := 0; i < len(rest)-4; i++ {
		if rest[i] == '\n' && rest[i+1] == ' ' && rest[i+2] == ' ' && rest[i+3] != ' ' && rest[i+3] != '-' && rest[i+3] != '#' {
			end = i
			break
		}
	}
	orchBlock := rest[:end]
	if !strings.Contains(orchBlock, "/var/vectis/generated:/var/vectis/generated") {
		t.Error("orchestrator block missing /var/vectis/generated bind mount — self-heal RegenerateConfigs will fail on legacy installs")
	}
	if strings.Contains(orchBlock, "/var/vectis/generated:/var/vectis/generated:ro") {
		t.Error("orchestrator /var/vectis/generated mount is :ro — RegenerateConfigs cannot atomic-write through it")
	}
}

// TestWebmailUsesVectisImageNotUpstream guards the v0.1.7-rc3 §13 fix.
// Pre-rc3 the compose used roundcube/roundcubemail:latest-fpm-alpine fronted
// by a separate vectis-webmail-nginx; the split required a shared docroot
// volume between the two for static-asset serving that we never set up,
// so /webmail/skins/elastic/styles.min.css 404'd to /index.php and the
// login page rendered fully unstyled since install.
func TestWebmailUsesVectisImageNotUpstream(t *testing.T) {
	data := testData()
	data.Webmail.Enabled = true
	files, err := Generate(data)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var compose string
	for _, f := range files {
		if f.RelPath == "docker-compose.yml" {
			compose = string(f.Content)
			break
		}
	}
	if !strings.Contains(compose, "ghcr.io/veltara-works/vectis-webmail:") {
		t.Error("webmail must use the Vectis-built image (ghcr.io/veltara-works/vectis-webmail) so the baked-in skin + entrypoint task land")
	}
	if strings.Contains(compose, "roundcube/roundcubemail:latest-fpm-alpine") {
		t.Error("webmail must NOT use upstream fpm-alpine (requires separate nginx + shared docroot we never set up)")
	}
	if strings.Contains(compose, "container_name: vectis-webmail-nginx") {
		t.Error("vectis-webmail-nginx service must be removed — apache image serves PHP + static in one container")
	}
	if strings.Contains(compose, "webmail-skin:") || strings.Contains(compose, "webmail-config:") || strings.Contains(compose, "webmail-nginx-config:") {
		t.Error("the three named volumes (webmail-skin, webmail-config, webmail-nginx-config) must be removed — none of them were ever engine-seeded")
	}
	if !strings.Contains(compose, "/var/www/html/config/config.vectis.inc.php:ro") {
		t.Error("Vectis config override must bind-mount to config.vectis.inc.php (not config.docker.inc.php; that fights the upstream entrypoint)")
	}
}

// TestWebmailHealthcheckIsNotPhpFpmHealthcheck guards against the v0.1.5
// regression where the webmail block used `php-fpm-healthcheck` — a binary
// that isn't in the upstream roundcubemail:fpm-alpine image. Containers
// stayed marked unhealthy on every fresh install. v0.1.6 replaces it with
// a busybox-ps probe of the FPM master process.
func TestWebmailHealthcheckIsNotPhpFpmHealthcheck(t *testing.T) {
	data := testData()
	data.Webmail.Enabled = true
	files, err := Generate(data)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var compose string
	for _, f := range files {
		if f.RelPath == "docker-compose.yml" {
			compose = string(f.Content)
			break
		}
	}
	if compose == "" {
		t.Fatal("docker-compose.yml not generated")
	}
	if !strings.Contains(compose, "vectis-webmail") {
		t.Fatal("webmail block not rendered despite Webmail.Enabled = true")
	}
	// Match only the test command line (the comment block above the
	// healthcheck mentions php-fpm-healthcheck for context, so a naive
	// substring search would false-positive).
	if strings.Contains(compose, `"php-fpm-healthcheck`) {
		t.Error("webmail healthcheck still uses php-fpm-healthcheck (not in roundcubemail:fpm-alpine image); replace with a probe that exists in the image")
	}
}

func TestClamAVNoneOmitsContainer(t *testing.T) {
	files, _ := Generate(testData()) // ClamAV profile is "none"
	var compose, clamdConf, antivirusConf string
	for _, f := range files {
		switch f.RelPath {
		case "docker-compose.yml":
			compose = string(f.Content)
		case "clamav/clamd.conf":
			clamdConf = string(f.Content)
		case "rspamd/antivirus.conf":
			antivirusConf = string(f.Content)
		}
	}
	if strings.Contains(compose, "vectis-clamav") {
		t.Error("docker-compose.yml should NOT contain clamav when profile is 'none'")
	}
	// Volume should also not be declared when profile is "none".
	if strings.Contains(compose, "clamav-data:") {
		t.Error("docker-compose.yml should NOT declare clamav-data volume when profile is 'none'")
	}
	// rspamd/antivirus.conf is always rendered (to keep the bind mount
	// path stable), but must contain no live clamav rules in profile=none.
	if strings.Contains(antivirusConf, "type = \"clamav\"") {
		t.Error("rspamd/antivirus.conf should be empty/disabled when profile is 'none'")
	}
	// clamd.conf is rendered even under profile "none" (Generate walks every
	// template); the container just never starts. The file must still be a
	// valid config — no bare directive whose profile-resolved knob is empty,
	// which clamd rejects as "Missing argument for option" (#44). Assert each
	// zero-valued knob is omitted rather than emitted with no argument.
	if clamdConf == "" {
		t.Fatal("clamav/clamd.conf was not rendered")
	}
	for _, knob := range []string{"MaxThreads", "StreamMaxLength", "MaxScanSize", "MaxFileSize"} {
		for _, line := range strings.Split(clamdConf, "\n") {
			if strings.TrimSpace(line) == knob || strings.TrimSpace(line) == knob+" " {
				t.Errorf("clamav/clamd.conf emits bare %q directive (no argument) under profile 'none' — clamd would refuse to start (#44)", knob)
			}
		}
	}
}

// TestClamAVProfileRenders covers the inverse: when profile is set, the
// compose block, bind mount, named volume, healthcheck, and rspamd
// antivirus rule must all be present. Locks in the v0.1.0 GA fix where
// every prior rc shipped without a buildable clamav image.
func TestClamAVProfileRenders(t *testing.T) {
	d := testData()
	d.ClamAV = resolveClamAVKnobs("small")
	files, _ := Generate(d)

	var compose, clamdConf, antivirusConf string
	for _, f := range files {
		switch f.RelPath {
		case "docker-compose.yml":
			compose = string(f.Content)
		case "clamav/clamd.conf":
			clamdConf = string(f.Content)
		case "rspamd/antivirus.conf":
			antivirusConf = string(f.Content)
		}
	}

	// Compose block + per-profile mem_limit + healthcheck + bind mounts.
	for _, want := range []string{
		"vectis-clamav",
		"image: ghcr.io/veltara-works/vectis-clamav:",
		"mem_limit: 2g", // small profile clamav ceiling (bumped from 1500m for DB-growth + reload headroom)
		"clamdscan --ping=1",
		"/var/vectis/generated/clamav/clamd.conf:/etc/clamav/clamd.conf:ro",
		"clamav-data:/var/lib/clamav",
		"/var/vectis/generated/rspamd/antivirus.conf:/etc/rspamd/local.d/antivirus.conf:ro",
	} {
		if !strings.Contains(compose, want) {
			t.Errorf("docker-compose.yml missing: %q", want)
		}
	}

	// clamd.conf knobs derived from profile.
	for _, want := range []string{
		"MaxThreads 4",
		"StreamMaxLength 25M",
		"TCPSocket 3310",
		"User clamav",
		"ConcurrentDatabaseReload no", // in-place reload to avoid the OOM spike
	} {
		if !strings.Contains(clamdConf, want) {
			t.Errorf("clamav/clamd.conf missing: %q", want)
		}
	}

	// rspamd antivirus rule wired to the sidecar.
	for _, want := range []string{
		`type = "clamav"`,
		`servers = "vectis-clamav:3310"`,
		`symbol = "CLAM_VIRUS"`,
	} {
		if !strings.Contains(antivirusConf, want) {
			t.Errorf("rspamd/antivirus.conf missing: %q", want)
		}
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
		name   string
		diffs  []FileDiff
		expect map[string]string
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

// TestResolveResourceKnobs locks down the per-service mem_limit matrix.
// Adding a service or changing a profile value must update this table
// (and bump the RAM matrix in the installation docs in lockstep).
func TestResolveResourceKnobs(t *testing.T) {
	tests := []struct {
		profile  string
		api      string
		postgres string
		valkey   string
		valkeyMM string
		traefik  string
	}{
		{"dev", "256m", "512m", "128m", "64mb", "128m"},
		{"small", "512m", "1g", "256m", "128mb", "128m"},
		{"production", "1g", "2g", "512m", "256mb", "256m"},
		{"enterprise", "2g", "4g", "1g", "512mb", "512m"},
		{"", "512m", "1g", "256m", "128mb", "128m"},        // empty → small default
		{"garbage", "512m", "1g", "256m", "128mb", "128m"}, // unknown → small default
	}
	for _, tt := range tests {
		t.Run(tt.profile, func(t *testing.T) {
			k := resolveResourceKnobs(tt.profile)
			if k.APIMemLimit != tt.api {
				t.Errorf("api: want %s, got %s", tt.api, k.APIMemLimit)
			}
			if k.PostgresMemLimit != tt.postgres {
				t.Errorf("postgres: want %s, got %s", tt.postgres, k.PostgresMemLimit)
			}
			if k.ValkeyMemLimit != tt.valkey {
				t.Errorf("valkey cgroup: want %s, got %s", tt.valkey, k.ValkeyMemLimit)
			}
			if k.ValkeyMaxMemory != tt.valkeyMM {
				t.Errorf("valkey --maxmemory: want %s, got %s", tt.valkeyMM, k.ValkeyMaxMemory)
			}
			if k.TraefikMemLimit != tt.traefik {
				t.Errorf("traefik: want %s, got %s", tt.traefik, k.TraefikMemLimit)
			}
		})
	}
}

// TestComposeMemLimitsRendered verifies the resolved profile actually
// reaches the compose YAML and ALL services carry a mem_limit. Guards
// against a future service being added to the template without a
// matching ResourceKnobs field — which would render as empty and
// produce invalid compose.
func TestComposeMemLimitsRendered(t *testing.T) {
	data := testData()
	data.Resources = resolveResourceKnobs("production")
	files, err := Generate(data)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var compose string
	for _, f := range files {
		if f.RelPath == "docker-compose.yml" {
			compose = string(f.Content)
			break
		}
	}

	// Production profile values that MUST appear after rendering.
	for _, want := range []string{
		"mem_limit: 1g",     // api / dovecot / rspamd / orchestrator (one of several)
		"mem_limit: 2g",     // postgres
		"mem_limit: 512m",   // valkey cgroup / postfix / webmail / loki / grafana
		"mem_limit: 256m",   // traefik / promtail
		"--maxmemory 256mb", // valkey internal cap
		"--maxmemory-policy allkeys-lru",
	} {
		if !strings.Contains(compose, want) {
			t.Errorf("compose missing %q under production profile", want)
		}
	}

	// Hard rule: no `mem_limit:` followed by empty value (which would mean a
	// service's template references an unresolved knob).
	if strings.Contains(compose, "mem_limit: \n") || strings.Contains(compose, "mem_limit:\n") {
		t.Error("compose has an empty mem_limit — a template references an unresolved ResourceKnobs field")
	}
}

// TestThirdPartyImagesDigestPinned enforces the REL-3 supply-chain invariant:
// every third-party image: line in the rendered compose must be digest-pinned
// (tag@sha256:<64-hex>), so an upstream tag move — or a registry compromise —
// cannot swap the bytes we run out from under us. The vectis-* images are
// exempt here: they carry a {{ .Version }} tag in the template and are
// digest-pinned at deploy time from the Ed25519-signed release manifest
// (pinComposeImageDigests). Without this guard a future edit could silently
// reintroduce a mutable bare tag.
func TestThirdPartyImagesDigestPinned(t *testing.T) {
	files, err := Generate(testData())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var compose string
	for _, f := range files {
		if f.RelPath == "docker-compose.yml" {
			compose = string(f.Content)
			break
		}
	}
	if compose == "" {
		t.Fatal("no docker-compose.yml rendered")
	}

	digestRe := regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	thirdParty := 0
	for _, line := range strings.Split(compose, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "image:") {
			continue
		}
		ref := strings.TrimSpace(strings.TrimPrefix(trimmed, "image:"))
		// vectis-* images are pinned separately (release manifest, deploy time).
		if strings.HasPrefix(ref, "ghcr.io/veltara-works/vectis-") {
			continue
		}
		thirdParty++
		if !digestRe.MatchString(ref) {
			t.Errorf("third-party image not digest-pinned: %q (must end in @sha256:<64-hex>)", ref)
		}
	}
	// Guard against the filter silently covering nothing (e.g. a rename that
	// makes every image match the vectis-* exemption): traefik/postgres/valkey
	// are always rendered, so we expect at least three.
	if thirdParty < 3 {
		t.Errorf("expected ≥3 third-party image lines, found %d — did the vectis-* filter over-match?", thirdParty)
	}
}

// TestSpamToJunkSieve verifies the global spam->Junk filing feature
// (rspamd.file_spam_to_junk). When enabled (the default, nil pointer),
// dovecot.conf wires the 2.4 spam_to_junk sieve_script (type = before), the milter_headers use-list adds
// the spam-header routine, and the sieve script renders; when explicitly
// disabled, none of those wire up (but the sieve file is still rendered, since
// the compose mount is unconditional).
func TestSpamToJunkSieve(t *testing.T) {
	get := func(files []GeneratedFile, relPath string) string {
		for _, f := range files {
			if f.RelPath == relPath {
				return string(f.Content)
			}
		}
		return ""
	}

	// Default (FileSpamToJunk nil) — feature ON.
	on, err := Generate(testData())
	if err != nil {
		t.Fatalf("Generate (default): %v", err)
	}
	if dc := get(on, "dovecot/dovecot.conf"); !strings.Contains(dc, "sieve_script spam_to_junk {") ||
		!strings.Contains(dc, "type = before") ||
		!strings.Contains(dc, "path = /etc/dovecot/sieve/spam-to-junk.sieve") {
		t.Error("default: dovecot.conf missing the 2.4 sieve_script spam_to_junk (type = before) wiring")
	}
	if !strings.Contains(get(on, "rspamd/milter_headers.conf"), `"spam-header"`) {
		t.Error("default: milter_headers.conf missing spam-header routine")
	}
	// Whitespace guard (Copilot review on PR #9): the {{- if }} trimming must
	// NOT fold "spam-header" onto the preceding inline-comment line — if it did,
	// rspamd would read it as commented-out and the array would lose the entry.
	// Assert the exact line break: comment line, newline, then its own element.
	if !strings.Contains(get(on, "rspamd/milter_headers.conf"), "visual.\n    \"spam-header\",") {
		t.Errorf("default: spam-header not on its own line (template trimming bug); got:\n%s", get(on, "rspamd/milter_headers.conf"))
	}
	// Same guard for dovecot: the conditional spam_to_junk sieve_script block must
	// start on its own line after the personal sieve_script block closes, not be
	// folded onto the closing brace by the {{- if }} trimming.
	if !strings.Contains(get(on, "dovecot/dovecot.conf"), "active_path = ~/.dovecot.sieve\n}\n\n# Global spam-filing") {
		t.Errorf("default: spam_to_junk block folded onto the personal block (template trimming bug); got dovecot.conf sieve section")
	}
	if sieve := get(on, "dovecot/spam-to-junk.sieve"); !strings.Contains(sieve, `fileinto :create "Junk"`) {
		t.Errorf("default: spam-to-junk.sieve missing fileinto rule; got:\n%s", sieve)
	}
	// Both spam signals must be matched: our own rspamd header AND the
	// SpamAssassin-standard flag set by upstream scanners (e.g. a cPanel host
	// forwarding mail in — re-scored low by rspamd, so it never gets our
	// X-Spam header). Copilot review on PR #187: without asserting the
	// X-Spam-Flag match here, the upstream-tagged condition could regress
	// silently since fileinto is still present.
	if sieve := get(on, "dovecot/spam-to-junk.sieve"); !strings.Contains(sieve, `header :is "X-Spam"      "Yes"`) {
		t.Errorf("default: spam-to-junk.sieve missing our own X-Spam header match; got:\n%s", sieve)
	}
	if sieve := get(on, "dovecot/spam-to-junk.sieve"); !strings.Contains(sieve, `header :is "X-Spam-Flag" "YES"`) {
		t.Errorf("default: spam-to-junk.sieve missing upstream X-Spam-Flag match; got:\n%s", sieve)
	}

	// Explicitly disabled — feature OFF.
	off := false
	d := testData()
	d.Rspamd.FileSpamToJunk = &off
	gen, err := Generate(d)
	if err != nil {
		t.Fatalf("Generate (disabled): %v", err)
	}
	if strings.Contains(get(gen, "dovecot/dovecot.conf"), "sieve_script spam_to_junk") {
		t.Error("disabled: dovecot.conf still wires the spam_to_junk sieve_script")
	}
	if strings.Contains(get(gen, "rspamd/milter_headers.conf"), `"spam-header"`) {
		t.Error("disabled: milter_headers.conf still adds spam-header")
	}
	if get(gen, "dovecot/spam-to-junk.sieve") == "" {
		t.Error("disabled: spam-to-junk.sieve should still be generated (mount is unconditional)")
	}
}

// TestDeriveInboundNotifyToken locks the derivation contract: deterministic,
// 64-hex, never equal to the input secret, distinct per secret, and the
// TemplateData method matches the package function.
func TestDeriveInboundNotifyToken(t *testing.T) {
	a := DeriveInboundNotifyToken("s1")
	if len(a) != 64 {
		t.Fatalf("expected 64 hex chars, got %d (%q)", len(a), a)
	}
	if a == "s1" {
		t.Fatal("derived token must not equal the secret")
	}
	if a != DeriveInboundNotifyToken("s1") {
		t.Fatal("derivation is not deterministic")
	}
	if a == DeriveInboundNotifyToken("s2") {
		t.Fatal("different secrets must derive different tokens")
	}
	d := TemplateData{API: config.APISecrets{Secret: "s1"}}
	if d.InboundNotifyToken() != a {
		t.Fatal("TemplateData.InboundNotifyToken() != DeriveInboundNotifyToken()")
	}
}

// TestInboundNotifyScript_DoesNotLeakMasterSecret is the regression guard for the
// audit finding: the generated Postfix inbound-notify script (world-readable in
// the container) must embed the derived token, NOT the master API secret.
func TestInboundNotifyScript_DoesNotLeakMasterSecret(t *testing.T) {
	const masterSecret = "super-master-secret-do-not-leak-0123456789abcdef"
	data := testData()
	data.API = config.APISecrets{Secret: masterSecret}

	files, err := Generate(data)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var script string
	for _, f := range files {
		if f.RelPath == "postfix/inbound-notify.sh" {
			script = string(f.Content)
			break
		}
	}
	if script == "" {
		t.Fatal("postfix/inbound-notify.sh was not generated")
	}
	if strings.Contains(script, masterSecret) {
		t.Error("inbound-notify.sh leaks the master API secret")
	}
	if !strings.Contains(script, DeriveInboundNotifyToken(masterSecret)) {
		t.Error("inbound-notify.sh does not contain the derived inbound-notify token")
	}
}

func TestDeriveGrafanaAdminPassword(t *testing.T) {
	const secret = "super-master-secret-do-not-leak-0123456789abcdef"
	pw := DeriveGrafanaAdminPassword(secret)
	if len(pw) != 64 {
		t.Fatalf("expected 64 hex chars, got %d (%q)", len(pw), pw)
	}
	if pw != DeriveGrafanaAdminPassword(secret) {
		t.Fatal("derivation is not deterministic")
	}
	if pw == DeriveGrafanaAdminPassword(secret+"x") {
		t.Fatal("different secrets must derive different passwords")
	}
	// Must be a one-way function of the secret, never a substring of it (the
	// pre-fix code used secret[:32], which exposed the master secret verbatim).
	if strings.Contains(secret, pw) || strings.Contains(pw, secret) {
		t.Fatal("derived password must not be a substring of (or contain) the master secret")
	}
	// Domain separation: a different label must not collide with the
	// inbound-notify token derived from the same secret.
	if pw == DeriveInboundNotifyToken(secret) {
		t.Fatal("grafana password must not equal the inbound-notify token (missing domain separation)")
	}
}

// TestRoundcubeConfig_DoesNotLeakMasterSecret is the regression guard for CFG-1
// (2026-07-06 prelaunch-delta audit). The webmail config is world-readable
// (0644 — www-data must read it), and the prior des_key was `.API.Secret` sliced
// to 24 chars, embedding the first 24 chars of the master API secret verbatim.
// The rendered des_key must now be the one-way-derived value, and the file must
// carry neither the full master secret nor its 24-char prefix.
//
// NB: the broader TestGenerateDoesNotEmitSecrets missed this because it matched
// the FULL secret with strings.Contains — a 24-char prefix of a longer secret
// never matched. This test asserts on the prefix specifically.
func TestRoundcubeConfig_DoesNotLeakMasterSecret(t *testing.T) {
	const masterSecret = "super-master-secret-do-not-leak-0123456789abcdef"
	data := testData()
	data.API = config.APISecrets{Secret: masterSecret}

	files, err := Generate(data)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var cfg string
	for _, f := range files {
		if f.RelPath == "webmail/roundcube.config.php" {
			cfg = string(f.Content)
			break
		}
	}
	if cfg == "" {
		t.Fatal("webmail/roundcube.config.php was not generated")
	}
	if strings.Contains(cfg, masterSecret) {
		t.Error("roundcube config leaks the full master API secret")
	}
	if strings.Contains(cfg, masterSecret[:24]) {
		t.Error("roundcube config leaks the 24-char master API secret prefix (CFG-1 regression)")
	}
	if !strings.Contains(cfg, "$config['des_key']") {
		t.Fatal("roundcube config does not set des_key")
	}
	if !strings.Contains(cfg, DeriveRoundcubeDESKey(masterSecret)) {
		t.Error("roundcube des_key is not the one-way-derived value")
	}
}

func TestDeriveRoundcubeDESKey(t *testing.T) {
	const secret = "super-master-secret-do-not-leak-0123456789abcdef"
	key := DeriveRoundcubeDESKey(secret)
	if len(key) != 24 {
		t.Fatalf("expected 24-char des_key, got %d (%q)", len(key), key)
	}
	if key != DeriveRoundcubeDESKey(secret) {
		t.Fatal("derivation is not deterministic")
	}
	if key == DeriveRoundcubeDESKey(secret+"x") {
		t.Fatal("different secrets must derive different keys")
	}
	// One-way: never a substring of (or containing) the master secret.
	if strings.Contains(secret, key) || strings.Contains(key, secret) {
		t.Fatal("derived des_key must not be a substring of the master secret")
	}
	// Domain separation from the other secret derivations off the same key.
	if key == DeriveInboundNotifyToken(secret)[:24] || key == DeriveGrafanaAdminPassword(secret)[:24] {
		t.Fatal("des_key must not collide with other derivations (missing domain separation)")
	}
}

// TestGenerateDoesNotEmitSecrets is the regression guard for the audit finding:
// Generate (rendered to disk at 0644 by WriteFiles, with no WriteSecrets on the
// config-apply / orchestrator paths) must NOT emit any secret file. Secrets are
// written exclusively by WriteSecrets at mode 0600 with one-way-derived values.
func TestGenerateDoesNotEmitSecrets(t *testing.T) {
	const masterSecret = "super-master-secret-do-not-leak-0123456789abcdef"
	data := testData()
	data.API = config.APISecrets{Secret: masterSecret}
	data.Observability.GrafanaEnabled = true

	files, err := Generate(data)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.RelPath, "secrets/") {
			t.Errorf("Generate emitted a secret file %q (mode %o) — secrets must come from WriteSecrets only", f.RelPath, f.Mode)
		}
		if strings.Contains(string(f.Content), masterSecret) {
			t.Errorf("generated file %q leaks the master API secret", f.RelPath)
		}
	}
}

// TestWriteSecretsGrafanaDerived verifies WriteSecrets writes a one-way-derived
// Grafana admin password at mode 0600 — never a substring of the master secret.
func TestWriteSecretsGrafanaDerived(t *testing.T) {
	const masterSecret = "super-master-secret-do-not-leak-0123456789abcdef"
	data := testData()
	data.API = config.APISecrets{Secret: masterSecret}
	data.Observability.GrafanaEnabled = true

	dir := t.TempDir()
	if err := WriteSecrets(dir, data); err != nil {
		t.Fatalf("WriteSecrets: %v", err)
	}
	path := filepath.Join(dir, "grafana_admin_password")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat grafana_admin_password: %v", err)
	}
	if info.Mode()&os.ModePerm != 0o600 {
		t.Errorf("grafana_admin_password mode = %o, want 0600", info.Mode()&os.ModePerm)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read grafana_admin_password: %v", err)
	}
	if string(got) != DeriveGrafanaAdminPassword(masterSecret) {
		t.Error("grafana_admin_password is not the derived value")
	}
	if strings.Contains(masterSecret, string(got)) {
		t.Error("grafana_admin_password is a substring of the master secret")
	}
}

// TestGenerateSecretConfigPerms is the regression for the audit finding that
// dovecot/postfix SQL conf files (and other configs embedding a credential)
// were written world-readable (0644), leaking DB role passwords to any local
// user. Generate must render a secret-bearing config at 0600 when its consumer
// reads it as root, while leaving non-secret configs at 0644 and the
// www-data-read webmail config readable.
func TestGenerateSecretConfigPerms(t *testing.T) {
	files, err := Generate(testData())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	byPath := make(map[string]GeneratedFile, len(files))
	for _, f := range files {
		byPath[f.RelPath] = f
	}

	// Secret-bearing configs read by a root container master process → 0600.
	secret0600 := []string{
		"dovecot/dovecot-sql.conf.ext",
		"postfix/pgsql_virtual_mailboxes.cf",
		"postfix/pgsql_virtual_domains.cf",
		"postfix/pgsql_virtual_aliases.cf",
		"rspamd/classifier-bayes.conf",
	}
	for _, p := range secret0600 {
		f, ok := byPath[p]
		if !ok {
			t.Errorf("%s not generated", p)
			continue
		}
		if !strings.Contains(string(f.Content), "secret_") {
			t.Errorf("%s expected to embed a DB/Valkey password but did not", p)
		}
		if f.Mode&os.ModePerm != 0o600 {
			t.Errorf("%s mode = %o, want 0600 (embeds a secret)", p, f.Mode&os.ModePerm)
		}
	}

	// The webmail config must be read by www-data inside the container, so it
	// stays group/other-readable. Its des_key is a one-way HMAC of the master
	// secret (CFG-1), and its session DB is SQLite — so it embeds no secret and
	// 0644 is safe.
	if f, ok := byPath["webmail/roundcube.config.php"]; ok {
		if f.Mode&os.ModePerm != 0o644 {
			t.Errorf("webmail/roundcube.config.php mode = %o, want 0644 (www-data reader)", f.Mode&os.ModePerm)
		}
	}

	// A representative config that carries no secret value stays at 0644.
	if f, ok := byPath["postfix/main.cf"]; ok {
		if strings.Contains(string(f.Content), "secret_") {
			t.Skip("postfix/main.cf unexpectedly embeds a secret; skipping 0644 assertion")
		}
		if f.Mode&os.ModePerm != 0o644 {
			t.Errorf("postfix/main.cf mode = %o, want 0644 (no secret material)", f.Mode&os.ModePerm)
		}
	}
}

// TestGenerateSecretConfigPermsShortPassword guards the fail-closed property
// raised in the PR #121 review: DB/Valkey passwords carry no min-length floor,
// so even a short-but-valid password must still force its secret-bearing config
// to 0600 rather than slip back to a world-readable 0644.
func TestGenerateSecretConfigPermsShortPassword(t *testing.T) {
	data := testData()
	data.Database.DovecotPassword = "q9" // intentionally short, still a real secret
	files, err := Generate(data)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for _, f := range files {
		if f.RelPath == "dovecot/dovecot-sql.conf.ext" {
			if !strings.Contains(string(f.Content), "q9") {
				t.Fatal("dovecot-sql.conf.ext did not embed the short password")
			}
			if f.Mode&os.ModePerm != 0o600 {
				t.Errorf("dovecot-sql.conf.ext mode = %o, want 0600 even for a short password", f.Mode&os.ModePerm)
			}
			return
		}
	}
	t.Fatal("dovecot/dovecot-sql.conf.ext not generated")
}

// TestRepairConfigPerms covers the startup self-heal that retroactively tightens
// secret-bearing configs on installs predating the 0600 change (a content-
// identical upgrade never rewrites them, so Generate's mode pick alone can't fix
// them). Verifies: secret config tightened; webmail + shell scripts excluded;
// non-secret untouched; already-tight unchanged; idempotent; nil-safe.
func TestRepairConfigPerms(t *testing.T) {
	dir := t.TempDir()
	const secret = "supersecretvalue123"
	secrets := &config.VectisSecrets{
		Database: config.DatabaseSecrets{DovecotPassword: secret},
	}

	write := func(rel string, mode os.FileMode, body string) string {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // defeat umask
			t.Fatal(err)
		}
		return p
	}

	sqlConf := write("dovecot/dovecot-sql.conf.ext", 0o644, "password="+secret)
	roundcube := write("webmail/roundcube.config.php", 0o644, "db_pass="+secret)
	initSh := write("postgres/init.sh", 0o755, "PW="+secret)
	plainConf := write("postfix/main.cf", 0o644, "myhostname = mail.example.com")
	alreadyTight := write("rspamd/classifier-bayes.conf", 0o600, "password="+secret)

	if err := RepairConfigPerms(dir, secrets); err != nil {
		t.Fatalf("RepairConfigPerms: %v", err)
	}

	checks := []struct {
		path string
		want os.FileMode
		why  string
	}{
		{sqlConf, 0o600, "secret-bearing config must be tightened"},
		{roundcube, 0o644, "webmail config excluded (www-data reader)"},
		{initSh, 0o755, "shell script excluded (must stay executable)"},
		{plainConf, 0o644, "non-secret config left untouched"},
		{alreadyTight, 0o600, "already-tight config unchanged"},
	}
	for _, c := range checks {
		info, err := os.Stat(c.path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != c.want {
			t.Errorf("%s: mode %o, want %o (%s)", c.path, info.Mode().Perm(), c.want, c.why)
		}
	}

	// A symlink inside genDir must not be followed — chmod must never escape
	// the generated tree onto the symlink's target.
	external := filepath.Join(t.TempDir(), "external-secret.conf")
	if err := os.WriteFile(external, []byte("password="+secret), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(external, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(dir, "rspamd", "link.conf")); err != nil {
		t.Fatal(err)
	}
	if err := RepairConfigPerms(dir, secrets); err != nil {
		t.Fatalf("RepairConfigPerms (symlink): %v", err)
	}
	if info, _ := os.Stat(external); info.Mode().Perm() != 0o644 {
		t.Errorf("symlink target chmod'd to %o; symlinks must not be followed", info.Mode().Perm())
	}

	// Idempotent: a second pass leaves the tightened file at 0600.
	if err := RepairConfigPerms(dir, secrets); err != nil {
		t.Fatalf("RepairConfigPerms (2nd pass): %v", err)
	}
	if info, _ := os.Stat(sqlConf); info.Mode().Perm() != 0o600 {
		t.Errorf("sqlConf after 2nd pass: %o, want 0600", info.Mode().Perm())
	}

	// nil secrets is a no-op, never a panic.
	if err := RepairConfigPerms(dir, nil); err != nil {
		t.Errorf("nil secrets should be a no-op, got: %v", err)
	}
}
