package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const randomSecretsYAML = `database:
  host: postgres
  port: 5432
  name: vectis
  superuser_password: "q8Zr2mVx7LkP4nWc9TbY3hJd6FsG1aEu"
  api_user: vectis_api
  api_password: "Xc4Vb7Nm2Qw9Er5Ty8Ui1Op3As6Df0Gh"
  postfix_user: vectis_postfix
  postfix_password: "Lk2Jh5Gf8Ds1Aq4Wz7Xc0Vb3Nm6Mq9Pe"
  dovecot_user: vectis_dovecot
  dovecot_password: "Rt6Yu9Io2Pa5Sd8Fg1Hj4Kl7Zx0Cv3Bn"
valkey:
  host: valkey
  port: 6379
  password: "Mn3Bv6Cx9Za2Sd5Fg8Hj1Kl4Qw7Er0Ty"
api:
  secret: "Ui5Op8As1Df4Gh7Jk0Lz3Xc6Vb9Nm2Qw5Er8Ty1Ui4Op7"
  admin_email: admin@example.com
  admin_password: "Gh2Jk5Lz8Xc1Vb4Nm7Qw0Er3Ty6Ui9Op"
  backup_encryption_key: "As8Df1Gh4Jk7Lz0Xc3Vb6Nm9Qw2Er5Ty"
orchestrator:
  token: "Zx4Cv7Bn0Mq3We6Rt9Yu2Io5Pa8Sd1Fg"
dkim:
  key_base_path: /var/vectis/dkim
`

func writeSecrets(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secrets.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckSecretsDefaults_FreshInstallPasses(t *testing.T) {
	r := checkSecretsDefaults(filepath.Join(t.TempDir(), "secrets.yaml"))
	if r.Status != "pass" {
		t.Fatalf("missing secrets.yaml: got %q (%s), want pass", r.Status, r.Message)
	}
}

func TestCheckSecretsDefaults_RandomValuesPass(t *testing.T) {
	r := checkSecretsDefaults(writeSecrets(t, randomSecretsYAML))
	if r.Status != "pass" {
		t.Fatalf("random secrets: got %q (%s), want pass", r.Status, r.Message)
	}
}

func TestCheckSecretsDefaults_DevDefaultsFailWithoutLeakingValues(t *testing.T) {
	body := strings.NewReplacer(
		"Lk2Jh5Gf8Ds1Aq4Wz7Xc0Vb3Nm6Mq9Pe", "vectis_dev_postfix",
		"Rt6Yu9Io2Pa5Sd8Fg1Hj4Kl7Zx0Cv3Bn", "vectis_dev_dovecot",
		"Mn3Bv6Cx9Za2Sd5Fg8Hj1Kl4Qw7Er0Ty", "vectis_dev_valkey",
	).Replace(randomSecretsYAML)
	r := checkSecretsDefaults(writeSecrets(t, body))
	if r.Status != "fail" {
		t.Fatalf("dev defaults: got %q, want fail", r.Status)
	}
	for _, want := range []string{"database.postfix_password", "database.dovecot_password", "valkey.password"} {
		if !strings.Contains(r.Message, want) {
			t.Errorf("message %q should name %s", r.Message, want)
		}
	}
	if strings.Contains(r.Message, "database.api_password") {
		t.Errorf("message %q names a field that holds a random value", r.Message)
	}
	if strings.Contains(r.Message+r.Value, "vectis_dev_") {
		t.Errorf("result must never echo a secret value: %+v", r)
	}
}

func TestCheckSecretsDefaults_ExamplePlaceholdersFail(t *testing.T) {
	body := strings.Replace(randomSecretsYAML,
		"Zx4Cv7Bn0Mq3We6Rt9Yu2Io5Pa8Sd1Fg", "CHANGE_ME_orchestrator_bearer_token", 1)
	r := checkSecretsDefaults(writeSecrets(t, body))
	if r.Status != "fail" || !strings.Contains(r.Message, "orchestrator.token") {
		t.Fatalf("CHANGE_ME placeholder: got %q (%s), want fail naming orchestrator.token", r.Status, r.Message)
	}
}

func TestCheckSecretsDefaults_UnparseableWarns(t *testing.T) {
	r := checkSecretsDefaults(writeSecrets(t, "not: [valid"))
	if r.Status != "warn" {
		t.Fatalf("unparseable: got %q, want warn", r.Status)
	}
}

// An installed box keeps the admin-password sentinel by design (admin init
// generates the real password), so it must not fail preflight; any other
// CHANGE_ME value, or a dev default, in that field still does.
func TestCheckSecretsDefaults_AdminPasswordSentinelPasses(t *testing.T) {
	body := strings.Replace(randomSecretsYAML,
		"Gh2Jk5Lz8Xc1Vb4Nm7Qw0Er3Ty6Ui9Op", adminPasswordSentinel, 1)
	if r := checkSecretsDefaults(writeSecrets(t, body)); r.Status != "pass" {
		t.Fatalf("installer-shaped secrets with the admin sentinel: got %q (%s), want pass", r.Status, r.Message)
	}
	body = strings.Replace(randomSecretsYAML,
		"Gh2Jk5Lz8Xc1Vb4Nm7Qw0Er3Ty6Ui9Op", "vectis_dev_admin", 1)
	if r := checkSecretsDefaults(writeSecrets(t, body)); r.Status != "fail" || !strings.Contains(r.Message, "api.admin_password") {
		t.Fatalf("dev default admin password: got %q (%s), want fail naming api.admin_password", r.Status, r.Message)
	}
}

// The shipped example must keep tripping the check: if someone renames the
// placeholders, preflight would silently stop catching an unedited copy.
func TestCheckSecretsDefaults_ShippedExampleFails(t *testing.T) {
	r := checkSecretsDefaults(filepath.Join("..", "..", "secrets.yaml.example"))
	if r.Status != "fail" {
		t.Fatalf("secrets.yaml.example: got %q (%s), want fail", r.Status, r.Message)
	}
}
