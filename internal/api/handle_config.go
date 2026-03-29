package api

import (
	"net/http"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/engine"
)

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

// redactedConfig is a copy of VectisConfig safe for API responses (no secrets).
type redactedConfig struct {
	Hostname  string                `json:"hostname"`
	TLS       redactedTLS           `json:"tls"`
	Resources config.ResourceConfig `json:"resources"`
	ClamAV    config.ClamAVConfig   `json:"clamav"`
	Rspamd    config.RspamdConfig   `json:"rspamd"`
	Postfix   config.PostfixConfig  `json:"postfix"`
	Dovecot   config.DovecotConfig  `json:"dovecot"`
	Backup    config.BackupConfig   `json:"backup"`
	Logging   config.LoggingConfig  `json:"logging"`
	Admin     config.AdminConfig    `json:"admin"`
}

type redactedTLS struct {
	Provider string `json:"provider"`
	Email    string `json:"email,omitempty"`
	CertPath string `json:"cert_path,omitempty"`
	KeyPath  string `json:"key_path,omitempty"`
}

type redactedSecrets struct {
	Database redactedDatabase `json:"database"`
	Valkey   redactedValkey   `json:"valkey"`
	API      redactedAPI      `json:"api"`
	DKIM     redactedDKIM     `json:"dkim"`
}

type redactedDatabase struct {
	Host            string `json:"host"`
	Port            int    `json:"port"`
	Name            string `json:"name"`
	APIUser         string `json:"api_user"`
	APIPassword     string `json:"api_password"`
	PostfixUser     string `json:"postfix_user"`
	PostfixPassword string `json:"postfix_password"`
	DovecotUser     string `json:"dovecot_user"`
	DovecotPassword string `json:"dovecot_password"`
}

type redactedValkey struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
}

type redactedAPI struct {
	Secret        string `json:"secret"`
	AdminEmail    string `json:"admin_email"`
	AdminPassword string `json:"admin_password"`
}

type redactedDKIM struct {
	KeyBasePath string `json:"key_base_path"`
}

type configResponse struct {
	Config  redactedConfig  `json:"config"`
	Secrets redactedSecrets `json:"secrets"`
}

type configValidateResponse struct {
	Valid    bool              `json:"valid"`
	Errors   []validationItem `json:"errors,omitempty"`
	Warnings []validationItem `json:"warnings,omitempty"`
}

type validationItem struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type configDiffResponse struct {
	HasChanges bool                   `json:"has_changes"`
	Files      []engine.FileDiff      `json:"files"`
	Actions    []engine.ServiceAction `json:"actions"`
}

type configApplyResponse struct {
	FilesWritten int                    `json:"files_written"`
	Diffs        []engine.FileDiff      `json:"diffs"`
	Actions      []engine.ServiceAction `json:"actions"`
	Results      []engine.ReloadResult  `json:"results,omitempty"`
	Success      bool                   `json:"success"`
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// handleGetConfig returns the current configuration with secrets redacted.
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if s.cfg == nil || s.secrets == nil {
		respondError(w, r, http.StatusServiceUnavailable, "CONFIG_UNAVAILABLE",
			"Configuration not loaded on this server instance")
		return
	}

	cfg := s.cfg
	secrets := s.secrets

	resp := configResponse{
		Config: redactedConfig{
			Hostname:  cfg.Hostname,
			TLS:       redactedTLS{Provider: cfg.TLS.Provider, Email: cfg.TLS.Email, CertPath: cfg.TLS.CertPath, KeyPath: cfg.TLS.KeyPath},
			Resources: cfg.Resources,
			ClamAV:    cfg.ClamAV,
			Rspamd:    cfg.Rspamd,
			Postfix:   cfg.Postfix,
			Dovecot:   cfg.Dovecot,
			Backup:    cfg.Backup,
			Logging:   cfg.Logging,
			Admin:     cfg.Admin,
		},
		Secrets: redactedSecrets{
			Database: redactedDatabase{
				Host:            secrets.Database.Host,
				Port:            secrets.Database.Port,
				Name:            secrets.Database.Name,
				APIUser:         secrets.Database.APIUser,
				APIPassword:     "***",
				PostfixUser:     secrets.Database.PostfixUser,
				PostfixPassword: "***",
				DovecotUser:     secrets.Database.DovecotUser,
				DovecotPassword: "***",
			},
			Valkey: redactedValkey{
				Host:     secrets.Valkey.Host,
				Port:     secrets.Valkey.Port,
				Password: "***",
			},
			API: redactedAPI{
				Secret:        "***",
				AdminEmail:    secrets.API.AdminEmail,
				AdminPassword: "***",
			},
			DKIM: redactedDKIM{
				KeyBasePath: secrets.DKIM.KeyBasePath,
			},
		},
	}

	respond(w, r, http.StatusOK, resp)
}

// handleValidateConfig validates the current configuration without applying.
func (s *Server) handleValidateConfig(w http.ResponseWriter, r *http.Request) {
	if s.cfg == nil || s.secrets == nil {
		respondError(w, r, http.StatusServiceUnavailable, "CONFIG_UNAVAILABLE",
			"Configuration not loaded on this server instance")
		return
	}

	cfgResult := config.ValidateConfig(s.cfg)
	secretsResult := config.ValidateSecrets(s.secrets)

	var errors []validationItem
	var warnings []validationItem

	for _, e := range cfgResult.Errors {
		errors = append(errors, validationItem{Field: e.Field, Message: e.Message})
	}
	for _, e := range cfgResult.Warnings {
		warnings = append(warnings, validationItem{Field: e.Field, Message: e.Message})
	}
	for _, e := range secretsResult.Errors {
		errors = append(errors, validationItem{Field: e.Field, Message: e.Message})
	}
	for _, e := range secretsResult.Warnings {
		warnings = append(warnings, validationItem{Field: e.Field, Message: e.Message})
	}

	valid := len(errors) == 0

	status := http.StatusOK
	if !valid {
		status = http.StatusUnprocessableEntity
	}

	respond(w, r, status, configValidateResponse{
		Valid:    valid,
		Errors:   errors,
		Warnings: warnings,
	})
}

// handleConfigDiff shows pending configuration changes.
func (s *Server) handleConfigDiff(w http.ResponseWriter, r *http.Request) {
	if s.cfg == nil || s.secrets == nil {
		respondError(w, r, http.StatusServiceUnavailable, "CONFIG_UNAVAILABLE",
			"Configuration not loaded on this server instance")
		return
	}

	// Query domains.
	domains, err := s.domains.List(r.Context(), nil)
	if err != nil {
		s.logger.Error("config diff: list domains failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list domains")
		return
	}

	// Generate expected configs.
	data := engine.NewTemplateData(s.cfg, s.secrets, domains)
	files, err := engine.Generate(data)
	if err != nil {
		s.logger.Error("config diff: generate failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "GENERATE_ERROR",
			"Failed to generate config files")
		return
	}

	// Compare against disk.
	diffs, err := engine.DiffFiles(s.genDir, files)
	if err != nil {
		s.logger.Error("config diff: diff failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "DIFF_ERROR",
			"Failed to compare config files")
		return
	}

	actions := engine.DetermineActions(diffs)

	respond(w, r, http.StatusOK, configDiffResponse{
		HasChanges: len(diffs) > 0,
		Files:      diffs,
		Actions:    actions,
	})
}

// handleConfigApply applies configuration changes and reloads/restarts services.
func (s *Server) handleConfigApply(w http.ResponseWriter, r *http.Request) {
	if s.cfg == nil || s.secrets == nil {
		respondError(w, r, http.StatusServiceUnavailable, "CONFIG_UNAVAILABLE",
			"Configuration not loaded on this server instance")
		return
	}

	// Query domains.
	domains, err := s.domains.List(r.Context(), nil)
	if err != nil {
		s.logger.Error("config apply: list domains failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list domains")
		return
	}

	// Generate expected configs.
	data := engine.NewTemplateData(s.cfg, s.secrets, domains)
	files, err := engine.Generate(data)
	if err != nil {
		s.logger.Error("config apply: generate failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "GENERATE_ERROR",
			"Failed to generate config files")
		return
	}

	// Diff first.
	diffs, err := engine.DiffFiles(s.genDir, files)
	if err != nil {
		s.logger.Error("config apply: diff failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "DIFF_ERROR",
			"Failed to compare config files")
		return
	}

	// Write files.
	if err := engine.WriteFiles(s.genDir, files); err != nil {
		s.logger.Error("config apply: write failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "WRITE_ERROR",
			"Failed to write config files")
		return
	}

	// Determine and execute service actions.
	actions := engine.DetermineActions(diffs)
	results := engine.ExecuteActions(actions)

	allSuccess := true
	for _, res := range results {
		if !res.Success {
			allSuccess = false
			break
		}
	}

	// Audit log.
	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "config.apply", "config", nil,
		map[string]any{"files_written": len(files), "diffs": len(diffs), "success": allSuccess}, &ip)

	respond(w, r, http.StatusOK, configApplyResponse{
		FilesWritten: len(files),
		Diffs:        diffs,
		Actions:      actions,
		Results:      results,
		Success:      allSuccess,
	})
}
