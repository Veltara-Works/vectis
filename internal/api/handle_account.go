package api

import (
	"context"
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
			"This install isn't licensed. Activate a Vectis Pro subscription on the License page first.")
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
	if err != nil {
		s.logger.Warn("billing portal session failed", "error", err, "tenant_id", runtimeCfg.TenantID)
		respondError(w, r, http.StatusBadGateway, "BILLING_PORTAL_FAILED",
			"Could not mint billing portal session: "+err.Error())
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
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
