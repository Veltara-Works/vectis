package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/validonx"
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
		// A tenant with no Stripe customer — free tier, or a manually-issued
		// (no-Stripe) Enterprise license — can't have a self-serve billing
		// portal. ValidonX signals this with a structured 409; surface a clean,
		// non-retryable response so the admin UI hides/disables "Manage Billing"
		// rather than showing a 502 with raw upstream JSON.
		var apiErr *validonx.APIError
		if errors.As(err, &apiErr) && apiErr.Code == validonx.ErrCodePortalNoStripeCustomer {
			s.audit.Log(r.Context(), &adminID, "billing.portal.unavailable", "billing", nil,
				map[string]string{"tenant_id": runtimeCfg.TenantID}, &ip)
			respondError(w, r, http.StatusConflict, "BILLING_PORTAL_UNAVAILABLE",
				"This plan is billed directly — there's no self-serve billing portal. Contact us to change your subscription.")
			return
		}
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
// admin button. Both fields are optional on the wire — the React UI sends an
// empty body and the handler sources owner_email/owner_name from the logged-in
// super-admin (the keyless checkout endpoint requires both). A caller may pass
// them explicitly to override; the buyer can still edit them on the Stripe page.
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
// KEYLESS Customer #2 endpoint (POST /api/v1/checkout/vectis-pro) and returns
// the URL for the admin UI to navigate to. No partner credential is involved —
// it was deliberately removed from the box so no Vx key ever lives on a
// customer machine; Vx price-locks the endpoint and validates the return URLs
// against its apex allowlist. The flow:
//
//  1. Caller is authenticated + super_admin (route-level).
//  2. Source owner_email/owner_name from the logged-in admin (the keyless
//     endpoint requires both); the request body may override.
//  3. SERVER-SET success/cancel URLs to allowlisted vectismail.com pages —
//     never the request host (that would be an open-redirect vector).
//  4. Call validonx.CreateVectisProCheckout; surface its error if any.
//  5. Audit-log the session mint and return {url, session_id, expires_at}.
//
// We do NOT require the install to be licensed — the whole point is
// bootstrapping a paid subscription from a Free install. After payment the
// customer lands on vectismail.com and Vx emails the activation credentials
// to paste on this install's License page.
func (s *Server) handleUpgradeCheckoutSession(w http.ResponseWriter, r *http.Request) {
	var req upgradeCheckoutRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	// Resolve the Vx base URL using the same DB-row > secrets.yaml precedence as
	// licensing and the billing-portal handler above — the keyless checkout
	// endpoint is served on the same host the box uses for licensing (confirmed
	// live on both validonx.com and api.validonx.com). Reading the runtime config
	// (not secrets-only) means an install configured purely via the admin License
	// page is honoured instead of silently falling back to the default host.
	cfgCtx, cfgCancel := context.WithTimeout(r.Context(), 5*time.Second)
	runtimeCfg, _ := validonx.LoadRuntimeConfig(cfgCtx, s.db, s.secretsValidonX())
	cfgCancel()
	baseURL := strings.TrimRight(runtimeCfg.BaseURL, "/")
	if baseURL == "" {
		baseURL = validonx.DefaultBaseURL
	}

	// owner_email / owner_name are REQUIRED by the keyless endpoint. Source
	// them server-side from the authenticated super-admin; the request body
	// may override (the React UI sends an empty body). The buyer can still
	// edit both on the Stripe-hosted page.
	adminID := getAdminID(r.Context())
	ownerEmail := strings.TrimSpace(req.OwnerEmail)
	ownerName := strings.TrimSpace(req.OwnerName)

	// Only hit the admin store when a required field is actually missing.
	if ownerEmail == "" || ownerName == "" {
		admin, err := s.admins.GetByID(r.Context(), adminID)
		if err != nil {
			// Don't fail outright — the request may carry usable fields and
			// owner_name has a safe fallback below. Log it so a broken admin
			// store is visible rather than silently degrading every checkout.
			s.logger.Warn("upgrade checkout: admin lookup failed; using request-supplied owner fields only",
				"error", err, "admin_id", adminID)
		} else if admin != nil && ownerEmail == "" {
			ownerEmail = strings.TrimSpace(admin.Email)
		}
	}

	// Derive owner_name from whichever email we actually ended up with —
	// request-supplied takes precedence over the admin's. Deriving from the
	// admin's email when the caller supplied a *different* owner_email would
	// mis-label the buyer; this keeps the name consistent with the address.
	if ownerName == "" {
		ownerName = deriveOwnerName(ownerEmail)
	}
	if ownerName == "" {
		ownerName = "Vectis Mail Admin"
	}
	if ownerEmail == "" {
		respondError(w, r, http.StatusInternalServerError, "OWNER_EMAIL_UNAVAILABLE",
			"Could not determine your account email to start checkout. Contact support.")
		return
	}

	// Return URLs are SERVER-SET to the allowlisted vectismail.com pages and
	// are NEVER derived from the request host — Vx independently validates them
	// against its apex return-URL allowlist, so a bug here cannot open-redirect
	// the customer off to a third party.
	const returnBase = "https://vectismail.com"
	successURL := returnBase + "/upgrade/success/?origin=install&session={CHECKOUT_SESSION_ID}"
	cancelURL := returnBase + "/upgrade/cancelled/?origin=install"

	checkoutReq := validonx.VectisProCheckoutRequest{
		OwnerEmail:               ownerEmail,
		OwnerName:                ownerName,
		SuccessURL:               successURL,
		CancelURL:                cancelURL,
		AllowPromotionCodes:      true,
		Locale:                   "en",
		BillingAddressCollection: "required",
		TaxIDCollection:          &validonx.TaxIDCollection{Enabled: true},
		ConsentCollection:        &validonx.ConsentCollection{TermsOfService: "required"},
		Metadata: map[string]string{
			"vm_source": "in-product",
		},
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	resp, err := validonx.CreateVectisProCheckout(ctx, nil,
		s.logger.With("component", "validonx.checkout"),
		baseURL, checkoutReq)

	ip := clientIP(r)
	if err != nil {
		s.logger.Warn("upgrade checkout session failed", "error", err)
		s.audit.Log(r.Context(), &adminID, "billing.checkout.mint_failed", "billing", nil,
			map[string]string{"error": err.Error()}, &ip)
		// Surface Vx's per-IP rate limit as 429 (not 502) so the UI and API
		// clients can back off and retry rather than treating it as a hard
		// upstream failure. Every other upstream error stays a 502.
		if errors.Is(err, validonx.ErrCheckoutRateLimited) {
			respondError(w, r, http.StatusTooManyRequests, "CHECKOUT_RATE_LIMITED",
				"Checkout is briefly rate-limited. Please wait a few seconds and try again.")
			return
		}
		respondError(w, r, http.StatusBadGateway, "CHECKOUT_FAILED",
			"Could not start checkout: "+err.Error())
		return
	}

	s.audit.Log(r.Context(), &adminID, "billing.checkout.mint", "billing", nil,
		map[string]string{"session_id": resp.SessionID}, &ip)

	respond(w, r, http.StatusOK, upgradeCheckoutResponse{
		URL:       resp.CheckoutURL,
		SessionID: resp.SessionID,
		ExpiresAt: resp.ExpiresAt,
	})
}

// deriveOwnerName produces a non-empty owner_name from an email local-part for
// the keyless checkout endpoint (which 422s without one). The buyer can edit it
// on the Stripe-hosted page; this is just a sensible pre-fill / fallback.
func deriveOwnerName(email string) string {
	local, _, found := strings.Cut(email, "@")
	if local = strings.TrimSpace(local); !found || local == "" {
		return ""
	}
	return local
}
