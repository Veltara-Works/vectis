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

	"github.com/Veltara-Works/vectis/internal/config"
)

// ---------------------------------------------------------------------------
// Error taxonomy — matches ValidonX ADR-009
// ---------------------------------------------------------------------------

const (
	ErrAuthFailed          = "BILLING.AUTH_FAILED"
	ErrAuthTokenExpired    = "BILLING.AUTH_TOKEN_EXPIRED"
	ErrSubscriptionNotFound = "BILLING.SUBSCRIPTION_NOT_FOUND"
	ErrSubscriptionInactive = "BILLING.SUBSCRIPTION_INACTIVE"
	ErrLicensingFailed     = "BILLING.LICENSING_FAILED"
	ErrLicensingExpired    = "BILLING.LICENSING_EXPIRED"
	ErrLicensingInvalid    = "BILLING.LICENSING_INVALID"
	ErrFeatureNotAvailable = "FEATURE_NOT_AVAILABLE"
	ErrLicenseExpired      = "LICENSE_EXPIRED"
)

// ---------------------------------------------------------------------------
// Subscription statuses — mirrors Stripe lifecycle states
// ---------------------------------------------------------------------------

// SubscriptionStatus mirrors the values ValidonX emits in
// licensing-resolve's `data.status` field. Six values; `suspended` (HTTP 403)
// and `revoked` (HTTP 404) are status codes, not enum values, and never
// appear here.
type SubscriptionStatus string

const (
	StatusActive   SubscriptionStatus = "active"
	StatusTrialing SubscriptionStatus = "trialing"
	StatusPastDue  SubscriptionStatus = "past_due"
	StatusPaused   SubscriptionStatus = "paused"
	StatusCanceled SubscriptionStatus = "canceled"
	StatusExpired  SubscriptionStatus = "expired"
)

// IsUsable returns true for statuses that should allow continued service.
//
// `past_due` is usable: ValidonX is still serving the customer through
// the dunning grace window (default 21 days per ADR-041 §3); `data.valid`
// is the authoritative gate, not status alone.
//
// `paused`, `canceled`, `expired` all surface in `data.status` with
// `data.valid = false` once their grace window (if any) has elapsed.
func (s SubscriptionStatus) IsUsable() bool {
	switch s {
	case StatusActive, StatusTrialing, StatusPastDue:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

// LicenseRequest is the payload sent to
// POST /api/v1/integration/licensing/resolve. Per ADR-041, the tenant is
// resolved by ValidonX's `ResolveTenantFromApiKey` middleware (X-API-Key
// header) — only `license_key` and the optional `features` filter are on
// the wire. `features` is omitted when nil/empty so ValidonX returns the
// full entitlement set per the 2026-04-26 sign-off.
type LicenseRequest struct {
	LicenseKey string   `json:"license_key"`
	Features   []string `json:"features,omitempty"`
}

// LicenseResponse is the inner `data` object returned by ValidonX's
// licensing-resolve endpoint. The transport envelope ({data, meta}) is
// unwrapped by ResolveLicense via licensingResolveEnvelope.
//
// Two distinct timeout fields per ADR-041 §2:
//   - GracePeriodEndsAt: when the customer drops to Free if they take no
//     action. Set only inside grace; nil otherwise.
//   - ExpiresAt: when the current paid period ends. For subscriptions,
//     mirrors `current_period_end`; for perpetual licenses, mirrors
//     `license.expires_at` (often nil).
type LicenseResponse struct {
	Valid              bool       `json:"valid"`
	Status             string     `json:"status"` // active, trialing, past_due, paused, canceled, expired
	AllowedFeatures    []string   `json:"allowed_features"`
	GracePeriodEndsAt  *time.Time `json:"grace_period_ends_at"` // nullable
	ExpiresAt          *time.Time `json:"expires_at"`           // nullable for perpetual licenses
}

// licensingResolveEnvelope wraps LicenseResponse for decoding. ValidonX
// returns `{data: {...}, meta: {request_id, api_version}}`; we discard
// meta and surface data as the caller-facing LicenseResponse.
type licensingResolveEnvelope struct {
	Data LicenseResponse `json:"data"`
	Meta struct {
		RequestID  string `json:"request_id"`
		APIVersion string `json:"api_version"`
	} `json:"meta"`
}

// BillingEvent is the payload sent to POST /v1/billing/events.
type BillingEvent struct {
	Type     string         `json:"type"` // server.startup, license.check, feature.usage, error
	TenantID string         `json:"tenant_id"`
	ServerID string         `json:"server_id"`
	Details  map[string]any `json:"details,omitempty"`
}

// BillingPortalRequest is the payload sent to
// POST /api/v1/integration/billing/portal-session. ValidonX mints a Stripe
// Billing Portal session for the tenant resolved from the X-API-Key header
// and returns the URL the customer should be redirected to. `return_url`
// tells Stripe where to bring the customer back after they finish; if empty
// ValidonX picks a sensible default (likely vectismail.com).
type BillingPortalRequest struct {
	ReturnURL string `json:"return_url,omitempty"`
}

// BillingPortalResponse is the inner `data` object returned by ValidonX's
// portal-session endpoint. The transport envelope ({data, meta}) is unwrapped
// by BillingPortalSession via billingPortalEnvelope.
type BillingPortalResponse struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// billingPortalEnvelope wraps BillingPortalResponse for decoding. Mirrors
// the envelope shape used by licensing-resolve.
type billingPortalEnvelope struct {
	Data BillingPortalResponse `json:"data"`
	Meta struct {
		RequestID  string `json:"request_id"`
		APIVersion string `json:"api_version"`
	} `json:"meta"`
}

// ErrCodePortalNoStripeCustomer is the ValidonX error code returned by the
// billing portal-session endpoint when the tenant has no Stripe customer —
// i.e. a free-tier install or a manually-issued (no-Stripe) Enterprise
// license. Callers branch on it to render "no self-serve billing portal"
// instead of surfacing a raw upstream error.
const ErrCodePortalNoStripeCustomer = "BILLING.PORTAL_SESSION_NO_STRIPE_CUSTOMER"

// APIError is a structured error returned by a ValidonX API call when the
// response carries an error code. Callers use errors.As to branch on Code /
// StatusCode (e.g. the billing portal's no-Stripe-customer 409). The Error()
// string preserves the prior "CODE: message (HTTP N)" format so existing logs
// are unchanged.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("validonx error (HTTP %d)", e.StatusCode)
	}
	return fmt.Sprintf("%s: %s (HTTP %d)", e.Code, e.Message, e.StatusCode)
}

// apiErrorResponse models ValidonX's error envelopes. Current ValidonX nests
// the error as {"error": {"code","message","type","status"}}; older/flat
// responses place code/message at the top level (and may carry a string
// "error"). The Error field is decoded as raw JSON so the top-level unmarshal
// never fails on its shape; resolved() prefers the nested form.
type apiErrorResponse struct {
	Code    string          `json:"code"`    // flat (legacy) shape
	Message string          `json:"message"` // flat (legacy) shape
	Error   json.RawMessage `json:"error"`   // nested object OR legacy string
}

// resolved returns the best available (code, message), preferring the nested
// `error` object over the flat top-level fields, and tolerating a legacy
// string `error`.
func (e apiErrorResponse) resolved() (code, message string) {
	code, message = e.Code, e.Message
	if len(e.Error) == 0 {
		return code, message
	}
	var obj struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(e.Error, &obj) == nil && (obj.Code != "" || obj.Message != "") {
		if obj.Code != "" {
			code = obj.Code
		}
		if obj.Message != "" {
			message = obj.Message
		}
		return code, message
	}
	// Legacy `"error": "some message"` string form.
	var s string
	if json.Unmarshal(e.Error, &s) == nil && s != "" && message == "" {
		message = s
	}
	return code, message
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client communicates with the ValidonX licensing API.
type Client struct {
	baseURL        string
	serviceKey     string
	tenantID       string
	subscriptionID string
	serverID       string
	// licenseKey is the ValidonX-issued license string for this install.
	// Sent on the wire as `data.license_key` to the resolve endpoint;
	// ValidonX uses it to locate the license row within the tenant
	// resolved from the API key.
	licenseKey string
	httpClient *http.Client
	logger     *slog.Logger
}

// NewClient creates a ValidonX API client from secrets configuration.
// Returns nil if ValidonX is not configured (free-tier mode).
func NewClient(secrets *config.ValidonXSecrets, logger *slog.Logger) *Client {
	if secrets == nil || secrets.BaseURL == "" || secrets.ServiceKey == "" {
		return nil
	}
	return &Client{
		baseURL:        secrets.BaseURL,
		serviceKey:     secrets.ServiceKey,
		tenantID:       secrets.TenantID,
		subscriptionID: secrets.SubscriptionID,
		serverID:       secrets.ServerID,
		licenseKey:     secrets.LicenseKey,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		logger: logger,
	}
}

// TenantID returns the configured tenant ID.
func (c *Client) TenantID() string {
	if c == nil {
		return ""
	}
	return c.tenantID
}

// ServerID returns the configured server ID.
func (c *Client) ServerID() string {
	if c == nil {
		return ""
	}
	return c.serverID
}

// Configured returns true if the client is non-nil and ready to use.
func (c *Client) Configured() bool {
	return c != nil && c.baseURL != ""
}

// ---------------------------------------------------------------------------
// API methods
// ---------------------------------------------------------------------------

// ResolveLicense calls POST /api/v1/integration/licensing/resolve to check
// license entitlements. The endpoint returns a `{data: {...}, meta: {...}}`
// envelope; this method unwraps the envelope and returns the inner
// LicenseResponse.
//
// Auth: X-API-Key (per ADR-041 §1). The endpoint is mounted under
// ValidonX's `v1/integration` route group with `ResolveTenantFromApiKey`
// middleware — the API key both authenticates the request and binds it
// to a tenant, so no separate token-exchange step is needed.
func (c *Client) ResolveLicense(ctx context.Context, req LicenseRequest) (*LicenseResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("validonx client not configured")
	}

	var env licensingResolveEnvelope
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/integration/licensing/resolve", req, &env, authAPIKey); err != nil {
		return nil, fmt.Errorf("%s: %w", ErrLicensingFailed, err)
	}
	return &env.Data, nil
}

// LogBillingEvent records a billing event with ValidonX. As of path-2
// (ValidonX PR #14, 2026-04-27) the path-1 endpoint /v1/billing/events
// has been retired and no replacement under /v1/integration/* has been
// defined yet. This method is a no-op until ValidonX confirms the new
// endpoint shape; the call surface is preserved so callers don't need
// to change.
//
// Existing callers (refreshLicense error path, usage.go telemetry) are
// best-effort and ignore the return value — the no-op transition is
// non-breaking.
func (c *Client) LogBillingEvent(ctx context.Context, event BillingEvent) error {
	if c == nil {
		return nil
	}
	c.logger.Debug("billing event suppressed (path-2 endpoint pending)",
		"type", event.Type, "tenant_id", event.TenantID)
	return nil
}

// BillingPortalSession calls POST /api/v1/integration/billing/portal-session
// to mint a Stripe Customer Portal session for the tenant resolved from
// the X-API-Key header. The customer is redirected to the returned URL to
// manage payment methods, view invoices, cancel, or upgrade their
// subscription. After they finish, Stripe redirects them back to
// `return_url` (or a ValidonX-side default if return_url is empty).
//
// Auth: X-API-Key (path-2). The caller (Vectis admin API) gates on
// super_admin + ValidonX-configured before invoking; ValidonX additionally
// re-validates the tenant has an active Stripe customer record.
//
// Endpoint shape was agreed in the 2026-05-08 ValidonX welcome-email
// coordination thread; ValidonX is building the endpoint in parallel
// with this Vectis-side caller. Until they ship, this method will return
// an error from the doJSON layer (most likely HTTP 404).
func (c *Client) BillingPortalSession(ctx context.Context, req BillingPortalRequest) (*BillingPortalResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("validonx client not configured")
	}

	var env billingPortalEnvelope
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/integration/billing/portal-session", req, &env, authAPIKey); err != nil {
		return nil, fmt.Errorf("mint billing-portal session: %w", err)
	}
	if env.Data.URL == "" {
		return nil, fmt.Errorf("validonx returned empty portal-session URL")
	}
	return &env.Data, nil
}

// CheckLicense is a convenience method that builds a LicenseRequest from the
// client's configured license_key and resolves it. Pass nil/empty features to
// request the full entitlement set (the recommended call for the gate's
// refresh path — gating decisions are made client-side off the cached
// AllowedFeatures list rather than asking per-feature on every check).
func (c *Client) CheckLicense(ctx context.Context, features []string) (*LicenseResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("validonx client not configured")
	}
	if c.licenseKey == "" {
		return nil, fmt.Errorf("validonx: license_key is empty (set validonx.license_key in secrets.yaml)")
	}

	return c.ResolveLicense(ctx, LicenseRequest{
		LicenseKey: c.licenseKey,
		Features:   features,
	})
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

// authMode selects how doJSON authenticates the outbound request.
//
//   - authAPIKey: send X-API-Key header with the configured serviceKey. This
//     is the path-2 model — ValidonX's ResolveTenantFromApiKey middleware
//     authenticates the request and resolves the tenant from the key. Use
//     this for every /api/v1/integration/* endpoint.
//
// The legacy authNone/authBearer modes (and the /v1/auth/login token flow they
// drove) were removed in v0.1.36 — ValidonX retired that route in PR #14 and
// every live call now uses X-API-Key.
type authMode int

const (
	authAPIKey authMode = iota
)

// doJSON performs an HTTP request with JSON body/response handling and
// authMode-driven auth header selection. See authMode docs for the modes.
func (c *Client) doJSON(ctx context.Context, method, path string, body any, dest any, auth authMode) error {
	var bodyReader io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	switch auth {
	case authAPIKey:
		req.Header.Set("X-API-Key", c.serviceKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("validonx unreachable: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB max
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp apiErrorResponse
		if json.Unmarshal(respBody, &errResp) == nil {
			if code, msg := errResp.resolved(); code != "" {
				return &APIError{StatusCode: resp.StatusCode, Code: code, Message: msg}
			}
		}
		return fmt.Errorf("validonx error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	if dest != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, dest); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}

	return nil
}
