package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/validonx"
)

// upgradeCheckout — constants for the in-product "Buy Pro" flow. These are
// product-wide values stable across all installs; they live here rather than
// in config because rotating them is a release event, not an install knob.
//
//   - upgradeProductCode: Vx's product-catalogue identifier for Vectis Mail.
//   - upgradePriceID:     the Stripe price_id for "Vectis Mail Pro USD$29/mo".
//     Sourced from /opt/vectis/.claude/.stripe.md and matches the price the
//     marketing-site Customer #2 endpoint resolves to. If/when we add tiers
//     (annual, multi-seat) this becomes a lookup, not a constant.
const (
	upgradeProductCode = "vectis-mail"
	upgradePriceID     = "price_1TUlqrBBhyrgaTgwLHyuvLVD"
)

// billingPortalSessionRequest is the inbound shape for
// POST /api/v1/account/billing-portal-session. `return_url` is optional
// on the wire — when omitted, the handler defaults it to the install's
// own /admin/license page so Stripe sends the customer back where they
// came from rather than to a ValidonX-side default. ValidonX itself
// 422-requires the field, so we always populate it before forwarding.
type billingPortalSessionRequest struct {
	ReturnURL string `json:"return_url,omitempty"`
}

// billingPortalSessionResponse is what the admin UI consumes. We return the
// URL rather than 302-redirecting from the API itself because the caller is
// fetch()-driven and wants to read the URL out of the JSON body before
// performing the navigation client-side.
type billingPortalSessionResponse struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// handleBillingPortalSession mints a Stripe Customer Portal session via
// ValidonX and returns the URL for the admin UI to navigate to. The flow:
//
//  1. Caller is authenticated + super_admin (route-level).
//  2. ValidonX must be configured (we have a tenant_id) — otherwise there's
//     no subscription to manage; bail with INSTALL_NOT_LICENSED.
//  3. Validate the optional return_url is a same-host absolute URL — Stripe
//     allows arbitrary HTTPS return URLs, but we keep it origin-restricted
//     so we can't be tricked into bouncing customers off-site.
//  4. Call ValidonX BillingPortalSession; surface their error code if any.
//  5. Audit-log the session mint and return {url, expires_at}.
//
// Notably: we do NOT require the license to be currently *valid*. A
// customer in past_due / cancelled state must be able to reach the portal —
// that's how they reactivate. The gate is "ValidonX is configured", not
// "tier is currently Pro". See project_billing_portal_proxy.md.
func (s *Server) handleBillingPortalSession(w http.ResponseWriter, r *http.Request) {
	var req billingPortalSessionRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	runtimeCfg, _ := validonx.LoadRuntimeConfig(r.Context(), s.db, s.secretsValidonX())
	if runtimeCfg == nil || !runtimeCfg.IsConfigured() || runtimeCfg.TenantID == "" {
		respondError(w, r, http.StatusForbidden, "INSTALL_NOT_LICENSED",
			"This install isn't licensed. Activate a Vectis Mail Pro subscription on the License page first.")
		return
	}

	returnURL := strings.TrimSpace(req.ReturnURL)
	if returnURL != "" {
		if err := validateReturnURL(returnURL, r); err != nil {
			respondError(w, r, http.StatusBadRequest, "INVALID_RETURN_URL", err.Error())
			return
		}
	} else {
		// Default to the License page on this install. ValidonX requires a
		// non-empty return_url; without this default, direct API callers
		// who omit return_url get a confusing BILLING_PORTAL_FAILED that
		// surfaces ValidonX's 422 "field is required" message. The React
		// /account/billing page always passes one, so this is a safety net
		// for non-UI callers.
		scheme := "https"
		if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
			scheme = "http"
		}
		returnURL = scheme + "://" + r.Host + "/admin/license"
	}

	client := validonx.NewClient(runtimeCfg.ToSecrets(), s.logger.With("component", "validonx.billing"))
	if client == nil || !client.Configured() {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR",
			"License client could not be initialised — check service_key and base_url on the License page")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	resp, err := client.BillingPortalSession(ctx, validonx.BillingPortalRequest{ReturnURL: returnURL})
	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	if err != nil {
		s.logger.Warn("billing portal session failed", "error", err, "tenant_id", runtimeCfg.TenantID)
		s.audit.Log(r.Context(), &adminID, "billing.portal.mint_failed", "billing", nil,
			map[string]string{"tenant_id": runtimeCfg.TenantID, "error": err.Error()}, &ip)
		respondError(w, r, http.StatusBadGateway, "BILLING_PORTAL_FAILED",
			"Could not mint billing portal session: "+err.Error())
		return
	}

	s.audit.Log(r.Context(), &adminID, "billing.portal.mint", "billing", nil,
		map[string]string{"tenant_id": runtimeCfg.TenantID}, &ip)

	respond(w, r, http.StatusOK, billingPortalSessionResponse{
		URL:       resp.URL,
		ExpiresAt: resp.ExpiresAt,
	})
}

// validateReturnURL accepts return URLs that share the request's host (or
// are relative paths) and rejects anything that would redirect the customer
// to a third party. The check is intentionally strict — Stripe will accept
// any HTTPS URL we pass, so any laxness here is exploitable as an open-redirect
// proxy through the ValidonX call chain.
func validateReturnURL(raw string, r *http.Request) error {
	u, err := url.Parse(raw)
	if err != nil {
		return invalidReturnURL("not a valid URL")
	}
	if u.Scheme != "" && u.Scheme != "https" && u.Scheme != "http" {
		return invalidReturnURL("only http/https schemes are allowed")
	}
	if u.Host == "" {
		// Relative path — fine; ValidonX will resolve against its default origin.
		return nil
	}
	reqHost := r.Host
	if i := strings.IndexByte(reqHost, ':'); i >= 0 {
		reqHost = reqHost[:i]
	}
	urlHost := u.Hostname()
	if !strings.EqualFold(urlHost, reqHost) {
		return invalidReturnURL("must point back to this install (host mismatch)")
	}
	return nil
}

type invalidReturnURLError string

func (e invalidReturnURLError) Error() string { return string(e) }

func invalidReturnURL(reason string) error { return invalidReturnURLError(reason) }

// upgradeCheckoutRequest is the inbound shape for the in-product "Buy Pro"
// admin button. Both fields are optional on the wire — when omitted, Stripe
// Checkout collects the email itself and Vx falls back to "Vectis Mail
// Customer" for the owner_name. Sending them lets us pre-fill the Stripe
// form for the logged-in admin so the customer doesn't retype.
type upgradeCheckoutRequest struct {
	OwnerEmail string `json:"owner_email,omitempty"`
	OwnerName  string `json:"owner_name,omitempty"`
}

// upgradeCheckoutResponse is what the admin UI consumes. As with
// billingPortalSessionResponse we return the URL rather than 302-redirecting
// from the API itself — the caller is fetch()-driven and performs the
// navigation client-side.
type upgradeCheckoutResponse struct {
	URL       string    `json:"url"`
	SessionID string    `json:"session_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// handleUpgradeCheckoutSession mints a Stripe Checkout session via Vx's
// Customer #1 partner-key endpoint and returns the URL for the admin UI to
// navigate to. The flow:
//
//  1. Caller is authenticated + super_admin (route-level).
//  2. Partner key must be present in secrets — without it the install can't
//     reach the endpoint at all; bail with INSTALL_NOT_PROVISIONED.
//  3. Determine tenant_id: pass-through from runtime config if set, omit
//     (new-signup branch) otherwise. Free-tier installs always hit the
//     new-signup branch since runtime config is empty.
//  4. Compute success/cancel URLs against the request host so the customer
//     comes back to *their* install, not vectismail.com.
//  5. Derive a stable install fingerprint (sha256 of /etc/machine-id +
//     hostname) for Vx's idempotency key.
//  6. Call validonx.CreateCheckoutSession; surface their error code if any.
//  7. Audit-log the session mint and return {url, session_id, expires_at}.
//
// Notably: we do NOT require the install to be licensed. The whole point of
// this endpoint is bootstrapping a paid subscription from a Free install.
// Pro installs *can* call it (e.g. to switch billing accounts) but the UI
// currently only surfaces it on the Free-tier path.
func (s *Server) handleUpgradeCheckoutSession(w http.ResponseWriter, r *http.Request) {
	var req upgradeCheckoutRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	secrets := s.secretsValidonX()
	if secrets == nil || secrets.CustomerOneKey == "" {
		respondError(w, r, http.StatusServiceUnavailable, "INSTALL_NOT_PROVISIONED",
			"This install can't initiate checkout — validonx.customer_one_key is not set in secrets.yaml. Contact support.")
		return
	}

	baseURL := strings.TrimRight(secrets.BaseURL, "/")
	if baseURL == "" {
		baseURL = validonx.DefaultBaseURL
	}

	// tenant_id: runtime config wins if present. Free installs have an empty
	// runtime config → empty TenantID → new-signup branch on Vx side. Pro
	// installs that hit this endpoint (currently no UI affordance for it)
	// would route to the upgrade-existing branch.
	runtimeCfg, _ := validonx.LoadRuntimeConfig(r.Context(), s.db, secrets)
	var tenantID string
	if runtimeCfg != nil {
		tenantID = runtimeCfg.TenantID
	}

	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	origin := scheme + "://" + r.Host
	successURL := origin + "/admin/license?checkout=success&session={CHECKOUT_SESSION_ID}"
	cancelURL := origin + "/admin/license?checkout=cancel"

	fingerprint := installFingerprint()

	checkoutReq := validonx.CheckoutCreateSessionRequest{
		ProductCode:   upgradeProductCode,
		PriceID:       upgradePriceID,
		CustomerEmail: strings.TrimSpace(req.OwnerEmail),
		CustomerName:  strings.TrimSpace(req.OwnerName),
		TenantID:      tenantID,
		SuccessURL:    successURL,
		CancelURL:     cancelURL,
		Metadata: map[string]string{
			"vectis_install_fingerprint": fingerprint,
			"source":                     "in-product",
		},
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	resp, err := validonx.CreateCheckoutSession(ctx, nil,
		s.logger.With("component", "validonx.checkout"),
		baseURL, secrets.CustomerOneKey, checkoutReq)

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	if err != nil {
		s.logger.Warn("upgrade checkout session failed",
			"error", err, "tenant_id", tenantID, "fingerprint", fingerprint)
		s.audit.Log(r.Context(), &adminID, "billing.checkout.mint_failed", "billing", nil,
			map[string]string{"tenant_id": tenantID, "error": err.Error()}, &ip)
		respondError(w, r, http.StatusBadGateway, "CHECKOUT_FAILED",
			"Could not start checkout: "+err.Error())
		return
	}

	s.audit.Log(r.Context(), &adminID, "billing.checkout.mint", "billing", nil,
		map[string]string{
			"tenant_id":   tenantID,
			"session_id":  resp.SessionID,
			"fingerprint": fingerprint,
		}, &ip)

	respond(w, r, http.StatusOK, upgradeCheckoutResponse{
		URL:       resp.CheckoutURL,
		SessionID: resp.SessionID,
		ExpiresAt: resp.ExpiresAt,
	})
}

// installFingerprint returns a stable, opaque identifier for this install,
// suitable as a Stripe Idempotency-Key seed on the Vx side. Derived from
// /etc/machine-id (the systemd/dbus standard install identifier) with
// hostname mixed in as a tiebreaker for containers that share machine-id
// from the host. Falls back to hostname-only if machine-id is unreadable
// (e.g. some non-systemd test environments), and to a constant final
// fallback so the field is never empty — Vx requires it.
func installFingerprint() string {
	var parts []string
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		parts = append(parts, strings.TrimSpace(string(b)))
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		parts = append(parts, host)
	}
	if len(parts) == 0 {
		parts = append(parts, "vectis-install-no-id")
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}
