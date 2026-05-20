package validonx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// ---------------------------------------------------------------------------
// Customer #1 (in-product) checkout — POST /api/v1/integration/checkout/create-session
// ---------------------------------------------------------------------------
//
// Distinct from the tenant-scoped Client methods: this endpoint authenticates
// with the *partner* key (customer_one_key) rather than a tenant's service_key.
// One key, every install — it authorises the Vectis Mail product as a whole
// to mint checkout sessions on behalf of un-tenanted Free installs that want
// to buy Pro. Vx scopes the key to `checkout:vectis-pro:create` only.
//
// Why this is a standalone function rather than a Client method: Free-tier
// installs cannot construct a *Client at all (NewClient returns nil without
// a tenant service_key), but they are the *primary* caller of this endpoint —
// the whole point is bootstrapping a paid subscription from a Free install.
// Keeping the partner-key flow out of the tenant-scoped Client also reduces
// the risk that future refactors accidentally cross-wire the two keys.

// CheckoutCreateSessionRequest is the body sent to Vx. Mirrors the contract
// recorded in reference_validonx_customer_one_key.md (Vx reply 2026-05-19 23:32 AEST).
//
// `TenantID` nil/empty → new-signup branch (Vx provisions a fresh tenant).
// `TenantID` non-empty → upgrade-existing branch (Vx attaches the new
// subscription to the named tenant; PR landed early on Vx side 2026-05-19).
//
// Vx forces `billing_address_collection: "required"` server-side; we do NOT
// pass it (Apple Pay name-fallback fix per Vx's "real money-losing bug"
// caught pre-merge by Copilot). `tax_id_collection` / `consent_collection`
// are NOT yet wired on the Customer #1 endpoint — parity with Customer #2
// is a Vx follow-up, flagged as non-blocking.
type CheckoutCreateSessionRequest struct {
	ProductCode    string            `json:"product_code"`              // required, e.g. "vectis-mail"
	PriceID        string            `json:"price_id"`                  // required, Stripe price_id
	CustomerEmail  string            `json:"customer_email,omitempty"`  // optional — Stripe collects if empty
	CustomerName   string            `json:"customer_name,omitempty"`   // optional — populates owner_name fallback
	TenantID       string            `json:"tenant_id,omitempty"`       // omitempty → new-signup; non-empty → upgrade-existing
	SuccessURL     string            `json:"success_url,omitempty"`     // include {CHECKOUT_SESSION_ID} placeholder
	CancelURL      string            `json:"cancel_url,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`        // must include vectis_install_fingerprint for Vx idempotency
}

// CheckoutCreateSessionResponse is the inner `data` object returned by Vx.
type CheckoutCreateSessionResponse struct {
	CheckoutURL string    `json:"checkout_url"`
	SessionID   string    `json:"session_id"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

// checkoutCreateSessionEnvelope wraps CheckoutCreateSessionResponse for decoding.
// Mirrors the {data, meta} envelope shared across all Vx integration endpoints.
type checkoutCreateSessionEnvelope struct {
	Data CheckoutCreateSessionResponse `json:"data"`
	Meta struct {
		RequestID  string `json:"request_id"`
		APIVersion string `json:"api_version"`
	} `json:"meta"`
}

// CreateCheckoutSession mints a Stripe Checkout session via Vx's Customer #1
// (partner-key-authenticated) endpoint. On success the caller redirects the
// customer's browser to `CheckoutURL`; on Stripe completion Vx provisions
// the subscription server-side and emails license credentials to
// `customer_email` (or the email Stripe collected during checkout).
//
// Pass nil for httpClient to use a sensible default (15s timeout).
func CreateCheckoutSession(ctx context.Context, httpClient *http.Client, logger *slog.Logger,
	baseURL, partnerKey string, req CheckoutCreateSessionRequest) (*CheckoutCreateSessionResponse, error) {

	if baseURL == "" {
		return nil, fmt.Errorf("validonx checkout: base_url is empty")
	}
	if partnerKey == "" {
		return nil, fmt.Errorf("validonx checkout: customer_one_key is empty (set validonx.customer_one_key in secrets.yaml)")
	}
	if req.ProductCode == "" || req.PriceID == "" {
		return nil, fmt.Errorf("validonx checkout: product_code and price_id are required")
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal checkout request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL+"/api/v1/integration/checkout/create-session",
		bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create checkout request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-API-Key", partnerKey)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("validonx unreachable: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read checkout response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp apiErrorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Code != "" {
			return nil, fmt.Errorf("%s: %s (HTTP %d)", errResp.Code, errResp.Message, resp.StatusCode)
		}
		return nil, fmt.Errorf("validonx checkout error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var env checkoutCreateSessionEnvelope
	if err := json.Unmarshal(respBody, &env); err != nil {
		return nil, fmt.Errorf("decode checkout response: %w", err)
	}
	if env.Data.CheckoutURL == "" {
		return nil, fmt.Errorf("validonx returned empty checkout_url")
	}

	if logger != nil {
		logger.Info("validonx checkout session minted",
			"session_id", env.Data.SessionID,
			"expires_at", env.Data.ExpiresAt,
			"tenant_id", req.TenantID,
			"product_code", req.ProductCode)
	}

	return &env.Data, nil
}
