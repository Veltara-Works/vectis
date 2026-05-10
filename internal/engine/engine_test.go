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
		ClamAV:   resolveClamAVKnobs("none"),
		Rspamd:   config.RspamdConfig{SpamThreshold: 15.0, RejectThreshold: 999, GreylistEnabled: false},
		Postfix:  config.PostfixConfig{MessageSizeLimit: 52428800, SmtpBanner: "$myhostname ESMTP"},
		Dovecot:  config.DovecotConfig{MailLocation: "maildir:/var/vectis/mail/%d/%n/Maildir", QuotaDefaultMB: 1024},
		Logging:  config.LoggingConfig{Level: "info", Driver: "json-file", MaxSizeMB: 50, MaxFiles: 5},
		Admin:    config.AdminConfig{ListenAddr: ":8080", SessionTTLHours: 24},
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
		"lmtp_smtputf8_enable = no",
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
		// Rspamd scoring + DKIM signing.
		`/var/vectis/generated/rspamd/dkim_signing.conf:/etc/rspamd/local.d/dkim_signing.conf:ro`,
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
	var compose, antivirusConf string
	for _, f := range files {
		switch f.RelPath {
		case "docker-compose.yml":
			compose = string(f.Content)
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
		"mem_limit: 1500m", // small profile
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
