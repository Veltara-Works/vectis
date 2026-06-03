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
// Vectis Mail Pro checkout
// ---------------------------------------------------------------------------
//
// The box mints Free→Pro upgrade sessions via Vx's keyless Customer #2 endpoint
// (see CreateVectisProCheckout below). The old keyed Customer #1 path, which
// required the customer_one_key partner credential, was removed so that no Vx
// key is ever held on a customer machine. The response types below are shared
// across Vx's checkout endpoints.

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

// ---------------------------------------------------------------------------
// Customer #2 (keyless) checkout — POST /api/v1/checkout/vectis-pro
// ---------------------------------------------------------------------------
//
// Anonymous endpoint: NO partner key, NO X-API-Key. Vx price-locks it to the
// public Vectis Mail Pro price server-side and validates success_url/cancel_url
// against its apex return-URL allowlist (vectismail.com). The in-product
// "Buy Pro" admin button drives checkout through here so that no partner
// credential ever lives on a customer machine — the keyed Customer #1 path
// (customer_one_key) was removed for exactly that reason. Contract re-confirmed
// against a live 422-probe 2026-06-03; the endpoint answers on both
// validonx.com and api.validonx.com, so the box reuses its configured base_url.

// VectisProCheckoutRequest is the body for the keyless checkout endpoint.
// owner_email + owner_name are REQUIRED (Vx 422s without them). The remaining
// fields mirror the marketing-site Customer #2 proxy so in-product and
// marketing purchases collect the same tax / ToS / billing details.
type VectisProCheckoutRequest struct {
	OwnerEmail               string             `json:"owner_email"`
	OwnerName                string             `json:"owner_name"`
	SuccessURL               string             `json:"success_url,omitempty"`
	CancelURL                string             `json:"cancel_url,omitempty"`
	AllowPromotionCodes      bool               `json:"allow_promotion_codes"`
	Locale                   string             `json:"locale,omitempty"`
	BillingAddressCollection string             `json:"billing_address_collection,omitempty"`
	TaxIDCollection          *TaxIDCollection   `json:"tax_id_collection,omitempty"`
	ConsentCollection        *ConsentCollection `json:"consent_collection,omitempty"`
	Metadata                 map[string]string  `json:"metadata,omitempty"`
}

// TaxIDCollection toggles Stripe's optional B2B tax-ID (ABN / VAT / GST) field.
type TaxIDCollection struct {
	Enabled bool `json:"enabled"`
}

// ConsentCollection drives Stripe's terms-of-service acceptance checkbox.
type ConsentCollection struct {
	TermsOfService string `json:"terms_of_service,omitempty"` // "required" | "none"
}

// laravelValidationError matches the keyless endpoint's 422 body shape
// ({message, errors}), which differs from the integration endpoints'
// {error, code, message}. Used only to surface a readable error string.
type laravelValidationError struct {
	Message string              `json:"message"`
	Errors  map[string][]string `json:"errors"`
}

// CreateVectisProCheckout mints a Stripe Checkout session via Vx's keyless
// Customer #2 endpoint. No credential is sent — the caller is anonymous and
// Vx rate-limits per source IP (6/min). On Stripe completion Vx provisions the
// subscription and emails the activation credentials to owner_email.
//
// Pass nil for httpClient to use a sensible default (15s timeout).
func CreateVectisProCheckout(ctx context.Context, httpClient *http.Client, logger *slog.Logger,
	baseURL string, req VectisProCheckoutRequest) (*CheckoutCreateSessionResponse, error) {

	if baseURL == "" {
		return nil, fmt.Errorf("validonx checkout: base_url is empty")
	}
	if req.OwnerEmail == "" || req.OwnerName == "" {
		return nil, fmt.Errorf("validonx checkout: owner_email and owner_name are required")
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal checkout request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL+"/api/v1/checkout/vectis-pro",
		bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create checkout request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("validonx unreachable: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read checkout response: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("validonx checkout is briefly rate-limited (HTTP 429) — please try again shortly")
	}
	if resp.StatusCode >= 400 {
		var verr laravelValidationError
		if json.Unmarshal(respBody, &verr) == nil && verr.Message != "" {
			return nil, fmt.Errorf("%s (HTTP %d)", verr.Message, resp.StatusCode)
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
		logger.Info("validonx keyless checkout session minted",
			"session_id", env.Data.SessionID,
			"expires_at", env.Data.ExpiresAt)
	}

	return &env.Data, nil
}
