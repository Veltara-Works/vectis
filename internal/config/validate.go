package config

import (
	"fmt"
	"regexp"
	"strings"
)

// validHostnameRe matches a simple hostname or FQDN (letters, digits, hyphens,
// dots). It intentionally does not cover every edge case in RFC 952/1123 but
// rejects obviously invalid values.
var validHostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$`)

// ValidationError describes a single validation problem.
type ValidationError struct {
	Field    string
	Message  string
	Severity string // "error" or "warning"
}

// ValidationResult collects all validation problems found during a check.
type ValidationResult struct {
	Errors   []ValidationError
	Warnings []ValidationError
}

// IsValid returns true when there are no errors. Warnings alone do not make
// the result invalid.
func (r *ValidationResult) IsValid() bool {
	return len(r.Errors) == 0
}

// AddError records a validation error.
func (r *ValidationResult) AddError(field, message string) {
	r.Errors = append(r.Errors, ValidationError{
		Field:    field,
		Message:  message,
		Severity: "error",
	})
}

// AddWarning records a validation warning.
func (r *ValidationResult) AddWarning(field, message string) {
	r.Warnings = append(r.Warnings, ValidationError{
		Field:    field,
		Message:  message,
		Severity: "warning",
	})
}

// ValidateConfig checks a VectisConfig for structural and semantic problems.
func ValidateConfig(cfg *VectisConfig) *ValidationResult {
	r := &ValidationResult{}

	// hostname
	if cfg.Hostname == "" {
		r.AddError("hostname", "hostname must not be empty")
	} else if !validHostnameRe.MatchString(cfg.Hostname) {
		r.AddError("hostname", "hostname does not look like a valid hostname")
	}

	// tls.provider
	switch cfg.TLS.Provider {
	case "letsencrypt", "custom", "":
		// ok
	default:
		r.AddError("tls.provider", "must be one of: letsencrypt, custom, or empty")
	}

	// tls.email required when provider is letsencrypt
	if cfg.TLS.Provider == "letsencrypt" && cfg.TLS.Email == "" {
		r.AddError("tls.email", "email is required when tls provider is letsencrypt")
	}

	// resources.profile
	switch cfg.Resources.Profile {
	case "dev", "small", "production", "enterprise", "":
		// ok
	default:
		r.AddError("resources.profile", "must be one of: dev, small, production, enterprise, or empty")
	}

	// clamav.profile
	switch cfg.ClamAV.Profile {
	case "none", "dev", "small", "production", "enterprise":
		// ok
	default:
		r.AddError("clamav.profile", "must be one of: none, dev, small, production, enterprise")
	}

	// rspamd.spam_threshold
	if cfg.Rspamd.SpamThreshold <= 0 {
		r.AddError("rspamd.spam_threshold", "must be greater than 0")
	}

	// postfix.message_size_limit
	if cfg.Postfix.MessageSizeLimit <= 0 {
		r.AddError("postfix.message_size_limit", "must be greater than 0")
	} else if cfg.Postfix.MessageSizeLimit > 104857600 {
		r.AddError("postfix.message_size_limit", "must not exceed 104857600 (100 MB)")
	}

	// postfix.strip_submission_extra_headers
	ValidateStripHeaders("postfix.strip_submission_extra_headers", cfg.Postfix.StripSubmissionExtraHeaders, r)

	// dovecot.quota_default_mb
	if cfg.Dovecot.QuotaDefaultMB <= 0 {
		r.AddError("dovecot.quota_default_mb", "must be greater than 0")
	}

	// logging.level
	switch cfg.Logging.Level {
	case "debug", "info", "warn", "error", "":
		// ok
	default:
		r.AddError("logging.level", "must be one of: debug, info, warn, error, or empty")
	}

	// admin.listen_addr
	if cfg.Admin.ListenAddr == "" {
		r.AddError("admin.listen_addr", "must not be empty")
	}

	// admin.session_ttl_hours
	if cfg.Admin.SessionTTLHours <= 0 {
		r.AddError("admin.session_ttl_hours", "must be greater than 0")
	}

	return r
}

// ValidateSecrets checks a VectisSecrets for missing or insecure values.
func ValidateSecrets(secrets *VectisSecrets) *ValidationResult {
	r := &ValidationResult{}

	// database passwords
	if secrets.Database.SuperuserPassword == "" {
		r.AddError("database.superuser_password", "must not be empty")
	}
	if secrets.Database.APIPassword == "" {
		r.AddError("database.api_password", "must not be empty")
	}
	if secrets.Database.PostfixPassword == "" {
		r.AddError("database.postfix_password", "must not be empty")
	}
	if secrets.Database.DovecotPassword == "" {
		r.AddError("database.dovecot_password", "must not be empty")
	}

	// database.name
	if secrets.Database.Name == "" {
		r.AddError("database.name", "must not be empty")
	}

	// valkey.password
	if secrets.Valkey.Password == "" {
		r.AddError("valkey.password", "must not be empty")
	}

	// api.secret
	if secrets.API.Secret == "" {
		r.AddError("api.secret", "must not be empty")
	} else if len(secrets.API.Secret) < 32 {
		r.AddError("api.secret", "must be at least 32 characters")
	}

	// api.admin_email
	if secrets.API.AdminEmail == "" {
		r.AddError("api.admin_email", "must not be empty")
	}

	// api.admin_password
	if secrets.API.AdminPassword == "" {
		r.AddError("api.admin_password", "must not be empty")
	} else if len(secrets.API.AdminPassword) < 8 {
		r.AddError("api.admin_password", "must be at least 8 characters")
	}

	// orchestrator.token
	if secrets.Orchestrator.Token == "" {
		r.AddError("orchestrator.token", "must not be empty")
	}

	// api.backup_encryption_key — required for production; backups must be encrypted
	if secrets.API.BackupEncryptionKey == "" {
		r.AddError("api.backup_encryption_key", "must not be empty — backup encryption is required; generate with: openssl rand -hex 32")
	}

	// rspamd.spamhaus_dqs_key — optional; when set it must look like a DQS key,
	// because it is interpolated into rspamd's config and into DNS names.
	if secrets.Rspamd.SpamhausDQSKey != "" && secrets.Rspamd.DQSKey() == "" {
		r.AddError("rspamd.spamhaus_dqs_key", SpamhausDQSKeyFormatError)
	} else if secrets.Rspamd.SpamhausDQSKey == "" {
		r.AddWarning("rspamd.spamhaus_dqs_key", SpamhausDQSKeyNotice)
	}

	return r
}

// ValidateStripHeaders checks a list of header names to strip from submitted
// mail, recording errors under field[i]. It is shared by ValidateConfig and the
// CLI's `config validate`/`apply`, which keeps its own validator.
//
// The names are interpolated into a generated Postfix regexp map, so only
// letters, digits, '-' and '_' are accepted: none is a regexp metacharacter or
// the '/' map delimiter, so a name can neither widen its own match ("Subject+"
// would also match Subject) nor inject or break a rule. Every real header name
// fits this set.
func ValidateStripHeaders(field string, names []string, r *ValidationResult) {
	for i, h := range names {
		f := fmt.Sprintf("%s[%d]", field, i)
		if h == "" {
			r.AddError(f, "must not be empty")
			continue
		}
		if len(h) > 78 {
			r.AddError(f, "must not exceed 78 characters")
			continue
		}
		if !validHeaderName(h) {
			r.AddError(f, "must be a header name of letters, digits, '-' and '_' only")
			continue
		}
		// Received, X-Originating-IP and Authentication-Results are always
		// handled by the built-in rules; listing them again would emit a
		// duplicate, unreachable rule.
		switch strings.ToLower(h) {
		case "received", "x-originating-ip", "authentication-results":
			r.AddError(f, "is already stripped by strip_submission_client_headers; remove it from this list")
			continue
		}
		// The submission cleanup service runs after the rspamd milter has
		// DKIM-signed the message, so removing a signed header breaks the
		// signature on every message sent from this host.
		if dkimSignedHeaders[strings.ToLower(h)] {
			r.AddError(f, "is covered by the DKIM signature; removing it would break DKIM on every outgoing message")
		}
	}
}

// dkimSignedHeaders is rspamd's default DKIM signing header list
// (default_dkim_headers in lualib/lua_ffi/dkim.lua, rspamd 4.0.1), which
// dkim_signing.conf does not override. Lower-case for case-insensitive lookup.
var dkimSignedHeaders = map[string]bool{
	"from": true, "sender": true, "reply-to": true, "subject": true,
	"date": true, "message-id": true, "to": true, "cc": true,
	"mime-version": true, "content-type": true, "content-transfer-encoding": true,
	"resent-to": true, "resent-cc": true, "resent-from": true,
	"resent-sender": true, "resent-message-id": true,
	"in-reply-to": true, "references": true,
	"list-id": true, "list-owner": true, "list-unsubscribe": true,
	"list-subscribe": true, "list-post": true,
	"openpgp": true, "autocrypt": true,
}

// validHeaderName reports whether s starts with a letter or digit and holds
// only letters, digits, '-' and '_'.
func validHeaderName(s string) bool {
	for i, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case (c == '-' || c == '_') && i > 0:
		default:
			return false
		}
	}
	return true
}
