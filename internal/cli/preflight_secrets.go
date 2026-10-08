package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/Veltara-Works/vectis/internal/config"
)

// knownDefaultPrefixes are value prefixes that only ever come from the public
// repository: the dev compose stack and CI use `vectis_dev_*`, and
// secrets.yaml.example ships `CHANGE_ME_*` placeholders. A production
// secrets.yaml holding either is using a credential anyone can read on GitHub.
// The installer generates random values, so a match means the file was
// hand-built from dev or example material (how prod ended up with the dev
// Postfix/Dovecot/Valkey passwords until 2026-10-04).
var knownDefaultPrefixes = []string{"vectis_dev_", "CHANGE_ME"}

// defaultSecretFields returns the yaml paths of credentials in s that still
// hold a known public default. Only field names are returned, never values.
func defaultSecretFields(s *config.VectisSecrets) []string {
	fields := []struct {
		path  string
		value string
	}{
		{"database.superuser_password", s.Database.SuperuserPassword},
		{"database.api_password", s.Database.APIPassword},
		{"database.postfix_password", s.Database.PostfixPassword},
		{"database.dovecot_password", s.Database.DovecotPassword},
		{"valkey.password", s.Valkey.Password},
		{"api.secret", s.API.Secret},
		{"api.admin_password", s.API.AdminPassword},
		{"api.backup_encryption_key", s.API.BackupEncryptionKey},
		{"orchestrator.token", s.Orchestrator.Token},
	}
	var hits []string
	for _, f := range fields {
		for _, p := range knownDefaultPrefixes {
			if strings.HasPrefix(f.value, p) {
				hits = append(hits, f.path)
				break
			}
		}
	}
	return hits
}

// checkSecretsDefaults fails preflight when an existing secrets.yaml (a
// reinstall, or a box assembled from dev material) holds a public default
// credential. A fresh host has no secrets.yaml yet, which passes.
func checkSecretsDefaults(path string) checkResult {
	const name = "Secrets"
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return checkResult{Name: name, Status: "pass", Value: "none yet (fresh install)"}
	}
	s, err := config.LoadSecrets(path)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return checkResult{Name: name, Status: "warn", Value: "not readable", Message: "Run as root to check secrets.yaml for default credentials"}
		}
		return checkResult{Name: name, Status: "warn", Value: "unparseable", Message: "Could not parse " + path}
	}
	if hits := defaultSecretFields(s); len(hits) > 0 {
		return checkResult{
			Name:    name,
			Status:  "fail",
			Value:   fmt.Sprintf("%d public default(s)", len(hits)),
			Message: "Replace with random values: " + strings.Join(hits, ", "),
		}
	}
	return checkResult{Name: name, Status: "pass", Value: "no known defaults"}
}
