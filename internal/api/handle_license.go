package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/validonx"
)

// blockedBaseURLIP reports whether an IP is one the ValidonX base_url must
// never target — private, link-local (incl. cloud-metadata 169.254.169.254),
// unspecified, or multicast. Loopback is handled by the caller (allowed as a
// literal dev hatch, blocked when a hostname resolves to it).
func blockedBaseURLIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified()
}

// validateLicenseBaseURL hardens the admin-settable ValidonX base_url against
// SSRF / service-key exfiltration (audit C-h1). The service_key is sent to this
// host as X-API-Key, so a super_admin (or a CSRF against one) must not be able
// to aim it at cloud-metadata or internal-network endpoints. Loopback is
// allowed as a local dev/self-host escape hatch; every other host must be https
// and must not be — or resolve to — a private, link-local, or unspecified
// address.
func validateLicenseBaseURL(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("base_url must be a valid absolute http(s) URL")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return nil
		}
		if blockedBaseURLIP(ip) {
			return fmt.Errorf("base_url must not point at a private or link-local address")
		}
	}
	if u.Scheme != "https" {
		return fmt.Errorf("base_url must use https")
	}
	// Reject hostnames that RESOLVE to a private/metadata address (audit P2-1):
	// the IP-literal checks above miss e.g. an internal DNS name pointing at
	// 169.254.169.254 or 10.x. Best-effort — a name that doesn't resolve can't
	// be an SSRF target (the outbound call just fails to connect), so a lookup
	// error is not itself a rejection. This is a set-time check, not a defence
	// against DNS rebinding (out of scope for this super_admin-gated setter).
	//
	// Bound the lookup with a deadline (audit §L L2): the default resolver has
	// no timeout, so a hostile/authoritative nameserver could otherwise stall
	// the super_admin's request indefinitely. 5s is ample for a set-time check.
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if ips, lookupErr := net.DefaultResolver.LookupIP(lookupCtx, "ip", host); lookupErr == nil {
		for _, ip := range ips {
			if ip.IsLoopback() || blockedBaseURLIP(ip) {
				return fmt.Errorf("base_url host %q resolves to a private or link-local address", host)
			}
		}
	}
	return nil
}

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
	// Offline is the offline JWT verifier's snapshot (the resilience layer).
	// Configured=false on installs with no [license].token — the UI then omits
	// the offline panel. Display-only; entitlement decisions are unaffected.
	Offline validonx.OfflineStatus `json:"offline"`
}

type setLicenseRequest struct {
	SubscriptionID string `json:"subscription_id"`
	TenantID       string `json:"tenant_id"`
	ServiceKey     string `json:"service_key"`
	BaseURL        string `json:"base_url"`
	ServerID       string `json:"server_id"`
	LicenseKey     string `json:"license_key"`
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

// loadValidonXConfig loads the merged ValidonX runtime config, decrypting the
// at-rest-encrypted credentials with the server's derived key (VX-CFG-1). All
// handler-layer reads go through here so none forgets the key.
func (s *Server) loadValidonXConfig(ctx context.Context) (*validonx.RuntimeConfig, error) {
	return validonx.LoadRuntimeConfig(ctx, s.db, s.secretsValidonX(), s.validonxEncKey)
}

// buildLicenseStateResponse composes the License page response shape from the
// merged DB+secrets runtime config and (optional) cached license entitlements.
func (s *Server) buildLicenseStateResponse(ctx context.Context) licenseStateResponse {
	resp := licenseStateResponse{Tier: validonx.TierFree}

	runtimeCfg, _ := s.loadValidonXConfig(ctx)
	if runtimeCfg != nil {
		resp.Configured = runtimeCfg.IsConfigured()
		resp.FromDB = runtimeCfg.FromDB
		resp.SubscriptionMasked = maskSubscriptionID(runtimeCfg.SubscriptionID)
		resp.TenantID = runtimeCfg.TenantID
		resp.ServerID = runtimeCfg.ServerID
		resp.BaseURL = runtimeCfg.BaseURL
	}

	resp.Offline = s.featureGate.OfflineLicenseStatus()

	if cache := s.featureGate.Cache(); cache != nil && resp.TenantID != "" {
		if cached, err := cache.GetCached(ctx, resp.TenantID); err == nil && cached != nil {
			// Only elevate the reported tier above Free when the license is
			// actually valid, mirroring currentTierAndFeatures / ResolveTier /
			// GrantsFeature (audit D-M1 / P2-4). Otherwise the License page
			// showed Pro for a revoked/suspended license, contradicting
			// /auth/me and the server-side gate. Status/dates still populate so
			// the page can explain the downgrade.
			if cached.LicenseData.Valid {
				resp.Tier = tierFromCachedFeatures(cached.Features)
			}
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

// currentTierAndFeatures returns the active tier ("free"/"pro"/"enterprise")
// and the cached allowed-features list for the current install. Returns
// TierFree + empty slice when ValidonX isn't configured, the runtime config
// has no tenant_id, or the cache hasn't been populated yet. Used by /auth/me
// to give the admin UI just enough state to render tier-aware affordances
// without exposing the sensitive identifiers that /api/v1/license carries.
func (s *Server) currentTierAndFeatures(ctx context.Context) (string, []string) {
	runtimeCfg, _ := s.loadValidonXConfig(ctx)
	if runtimeCfg == nil || runtimeCfg.TenantID == "" {
		return validonx.TierFree, []string{}
	}
	cache := s.featureGate.Cache()
	if cache == nil {
		return validonx.TierFree, []string{}
	}
	cached, err := cache.GetCached(ctx, runtimeCfg.TenantID)
	if err != nil || cached == nil {
		return validonx.TierFree, []string{}
	}
	// Honour the authoritative Valid flag, mirroring GrantsFeature and
	// validonx.ResolveTier (audit D-M1): a license ValidonX has marked
	// invalid (revoked/suspended/past-dunning) with a surviving cache row
	// must present as Free so the UI stops offering Pro/Enterprise
	// affordances the server gate will now reject.
	if !cached.LicenseData.Valid {
		return validonx.TierFree, []string{}
	}
	return tierFromCachedFeatures(cached.Features), cached.Features
}

// tierFromCachedFeatures mirrors validonx.tierFromFeatures (which is package-
// internal). Kept here so the API doesn't need to expose the helper. Must stay
// in sync with the validonx feature lists — TestTierFromCachedFeaturesNoDrift
// fails the build if an Enterprise/Pro feature is added there but not here.
func tierFromCachedFeatures(features []string) string {
	hasEnterprise := false
	hasPro := false
	for _, f := range features {
		switch f {
		case validonx.FeatureSAMLSSO, validonx.FeatureSLA, validonx.FeatureDSAR, validonx.FeatureSCIM:
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

	current, _ := s.loadValidonXConfig(r.Context())
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
	if req.LicenseKey != "" {
		merged.LicenseKey = req.LicenseKey
	}
	if merged.BaseURL == "" {
		merged.BaseURL = validonx.DefaultBaseURL
	}
	if err := validateLicenseBaseURL(r.Context(), merged.BaseURL); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_BASE_URL", err.Error())
		return
	}

	if !merged.IsConfigured() {
		respondError(w, r, http.StatusBadRequest, "INCOMPLETE_LICENSE",
			"License requires at least base_url + service_key. Paste both from your ValidonX subscription details.")
		return
	}
	if merged.LicenseKey == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_LICENSE_KEY",
			"License key is required. Paste the 'Subscription License' string (VLDX-...) from your ValidonX dashboard.")
		return
	}
	// tenant_id is required because ValidonX never returns it on the wire
	// (path-2 ADR-041: tenant is bound to the API key on their side and
	// never surfaces in resolve responses). Without it, FeatureGate.Cache
	// primes against an empty key while subsequent reads use the populated
	// key from cache lookups elsewhere — yielding a half-broken state where
	// the gate allows Pro endpoints but /auth/me and /api/v1/license still
	// report tier=free. See project_license_first_time_from_free.md.
	if merged.TenantID == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_TENANT_ID",
			"Tenant ID is required. Paste the tenant_id from your ValidonX Overview tab.")
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
			"ValidonX rejected the license. Check the service key and that the subscription is active.")
		return
	}
	if !resp.Valid {
		respondError(w, r, http.StatusUnprocessableEntity, "LICENSE_INACTIVE",
			"ValidonX returned subscription status \""+resp.Status+"\". License is not active.")
		return
	}

	adminID := getAdminID(r.Context())
	if err := validonx.SaveRuntimeConfig(r.Context(), s.db, s.logger, merged, adminID, s.validonxEncKey); err != nil {
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
	current, _ := s.loadValidonXConfig(r.Context())

	if err := validonx.ClearRuntimeConfig(r.Context(), s.db, s.logger); err != nil && !errors.Is(err, context.Canceled) {
		s.logger.Error("clear validonx runtime config failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to clear license")
		return
	}

	if cache := s.featureGate.Cache(); cache != nil && current != nil && current.TenantID != "" {
		_ = cache.DeleteCached(r.Context(), current.TenantID)
	}

	postClearCfg, _ := s.loadValidonXConfig(r.Context())
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
