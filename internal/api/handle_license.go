package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/validonx"
)

// licenseStateResponse is the shape returned by GET / POST / DELETE /api/v1/license.
type licenseStateResponse struct {
	Configured         bool      `json:"configured"`
	FromDB             bool      `json:"from_db"`
	Tier               string    `json:"tier"` // "free" | "pro" | "enterprise"
	Status             string    `json:"status,omitempty"`
	SubscriptionMasked string    `json:"subscription_id_masked,omitempty"`
	TenantID           string    `json:"tenant_id,omitempty"`
	ServerID           string    `json:"server_id,omitempty"`
	BaseURL            string    `json:"base_url,omitempty"`
	LastCheckAt        time.Time `json:"last_check_at,omitempty"`
	ExpiresAt          time.Time `json:"expires_at,omitempty"`
	GraceRemainingDays int       `json:"grace_remaining_days,omitempty"`
}

type setLicenseRequest struct {
	SubscriptionID string `json:"subscription_id"`
	TenantID       string `json:"tenant_id"`
	ServiceKey     string `json:"service_key"`
	BaseURL        string `json:"base_url"`
	ServerID       string `json:"server_id"`
}

// maskSubscriptionID returns "sub_****<last6>" for non-empty input, else "".
// The full id is sensitive (it identifies a paying customer) so we never
// return it via GET — only the last 6 chars for visual confirmation.
func maskSubscriptionID(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 6 {
		return "sub_****"
	}
	return "sub_****" + s[len(s)-6:]
}

// secretsValidonX returns the optional ValidonXSecrets block from the loaded
// secrets.yaml. Returns nil for installs that don't pre-configure ValidonX.
func (s *Server) secretsValidonX() *config.ValidonXSecrets {
	if s.secrets == nil {
		return nil
	}
	return s.secrets.ValidonX
}

// buildLicenseStateResponse composes the License page response shape from the
// merged DB+secrets runtime config and (optional) cached license entitlements.
func (s *Server) buildLicenseStateResponse(ctx context.Context) licenseStateResponse {
	resp := licenseStateResponse{Tier: validonx.TierFree}

	runtimeCfg, _ := validonx.LoadRuntimeConfig(ctx, s.db, s.secretsValidonX())
	if runtimeCfg != nil {
		resp.Configured = runtimeCfg.IsConfigured()
		resp.FromDB = runtimeCfg.FromDB
		resp.SubscriptionMasked = maskSubscriptionID(runtimeCfg.SubscriptionID)
		resp.TenantID = runtimeCfg.TenantID
		resp.ServerID = runtimeCfg.ServerID
		resp.BaseURL = runtimeCfg.BaseURL
	}

	if cache := s.featureGate.Cache(); cache != nil && resp.TenantID != "" {
		if cached, err := cache.GetCached(ctx, resp.TenantID); err == nil && cached != nil {
			resp.Tier = tierFromCachedFeatures(cached.Features)
			resp.Status = cached.Status
			resp.LastCheckAt = cached.LastCheckAt
			resp.ExpiresAt = cached.ExpiresAt
			if remaining := time.Until(cached.ExpiresAt); remaining > 0 {
				resp.GraceRemainingDays = int(remaining / (24 * time.Hour))
			}
		}
	}

	return resp
}

// tierFromCachedFeatures mirrors validonx.tierFromFeatures (which is package-
// internal). Kept here so the API doesn't need to expose the helper.
func tierFromCachedFeatures(features []string) string {
	hasEnterprise := false
	hasPro := false
	for _, f := range features {
		switch f {
		case validonx.FeatureMultiTenant, validonx.FeatureDeliverability, validonx.FeatureSLA:
			hasEnterprise = true
		case validonx.FeatureAnalytics, validonx.FeatureOIDCSSO, validonx.FeatureCustomBranding,
			validonx.FeatureAdvancedSpam, validonx.FeaturePrioritySupport:
			hasPro = true
		}
	}
	if hasEnterprise {
		return validonx.TierEnterprise
	}
	if hasPro {
		return validonx.TierPro
	}
	return validonx.TierFree
}

func (s *Server) handleGetLicense(w http.ResponseWriter, r *http.Request) {
	respond(w, r, http.StatusOK, s.buildLicenseStateResponse(r.Context()))
}

// handleSetLicense merges the requested fields with the current runtime
// config, validates against the live ValidonX API, persists the result, and
// atomically swaps the running gate client.
func (s *Server) handleSetLicense(w http.ResponseWriter, r *http.Request) {
	var req setLicenseRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	current, _ := validonx.LoadRuntimeConfig(r.Context(), s.db, s.secretsValidonX())
	merged := *current
	if req.SubscriptionID != "" {
		merged.SubscriptionID = req.SubscriptionID
	}
	if req.TenantID != "" {
		merged.TenantID = req.TenantID
	}
	if req.ServiceKey != "" {
		merged.ServiceKey = req.ServiceKey
	}
	if req.BaseURL != "" {
		merged.BaseURL = req.BaseURL
	}
	if req.ServerID != "" {
		merged.ServerID = req.ServerID
	}
	if merged.BaseURL == "" {
		merged.BaseURL = validonx.DefaultBaseURL
	}

	if !merged.IsConfigured() {
		respondError(w, r, http.StatusBadRequest, "INCOMPLETE_LICENSE",
			"License requires at least base_url + service_key. Paste both from your ValidonX subscription details.")
		return
	}

	probe := validonx.NewClient(merged.ToSecrets(), s.logger.With("component", "validonx.activate"))
	if probe == nil || !probe.Configured() {
		respondError(w, r, http.StatusBadRequest, "INVALID_LICENSE_CONFIG",
			"License configuration could not be initialised — check service_key and base_url")
		return
	}

	probeCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	resp, err := probe.CheckLicense(probeCtx, nil)
	if err != nil {
		s.logger.Warn("license validation failed", "error", err)
		respondError(w, r, http.StatusUnprocessableEntity, "LICENSE_VALIDATION_FAILED",
			"ValidonX rejected the license: "+err.Error())
		return
	}
	if !resp.Valid {
		respondError(w, r, http.StatusUnprocessableEntity, "LICENSE_INACTIVE",
			"ValidonX returned subscription status \""+resp.Status+"\". License is not active.")
		return
	}

	adminID := getAdminID(r.Context())
	if err := validonx.SaveRuntimeConfig(r.Context(), s.db, s.logger, merged, adminID); err != nil {
		s.logger.Error("save validonx runtime config failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to persist license")
		return
	}

	// Prime the cache so subsequent FeatureGate calls see the new tier
	// without waiting for the first lazy refresh.
	if cache := s.featureGate.Cache(); cache != nil {
		if cacheErr := cache.UpdateCache(r.Context(), merged.TenantID, merged.SubscriptionID, resp); cacheErr != nil {
			s.logger.Warn("prime license cache failed", "error", cacheErr)
		}
	}

	s.featureGate.SwapClient(probe)
	s.usageReporter = validonx.NewUsageReporter(probe, s.db, s.logger.With("component", "usage-reporter"))

	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "license.activate", "license", nil,
		map[string]string{"tenant_id": merged.TenantID, "status": resp.Status}, &ip)

	respond(w, r, http.StatusOK, s.buildLicenseStateResponse(r.Context()))
}

// handleDeleteLicense clears the validonx_config row, swaps the gate client,
// and removes the cached license row. If secrets.yaml still configures
// ValidonX the install reverts to that; otherwise it drops to Free tier.
func (s *Server) handleDeleteLicense(w http.ResponseWriter, r *http.Request) {
	current, _ := validonx.LoadRuntimeConfig(r.Context(), s.db, s.secretsValidonX())

	if err := validonx.ClearRuntimeConfig(r.Context(), s.db, s.logger); err != nil && !errors.Is(err, context.Canceled) {
		s.logger.Error("clear validonx runtime config failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to clear license")
		return
	}

	if cache := s.featureGate.Cache(); cache != nil && current != nil && current.TenantID != "" {
		_ = cache.DeleteCached(r.Context(), current.TenantID)
	}

	postClearCfg, _ := validonx.LoadRuntimeConfig(r.Context(), s.db, s.secretsValidonX())
	var newClient *validonx.Client
	if postClearCfg != nil && postClearCfg.IsConfigured() {
		newClient = validonx.NewClient(postClearCfg.ToSecrets(), s.logger.With("component", "validonx"))
	}
	s.featureGate.SwapClient(newClient)
	if newClient.Configured() {
		s.usageReporter = validonx.NewUsageReporter(newClient, s.db, s.logger.With("component", "usage-reporter"))
	} else {
		s.usageReporter = nil
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	tenantID := ""
	if current != nil {
		tenantID = current.TenantID
	}
	s.audit.Log(r.Context(), &adminID, "license.deactivate", "license", nil,
		map[string]string{"tenant_id": tenantID}, &ip)

	respond(w, r, http.StatusOK, s.buildLicenseStateResponse(r.Context()))
}
