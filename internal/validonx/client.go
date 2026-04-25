package validonx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
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

type SubscriptionStatus string

const (
	StatusActive                    SubscriptionStatus = "active"
	StatusTrialing                  SubscriptionStatus = "trialing"
	StatusPaused                    SubscriptionStatus = "paused"
	StatusScheduledForCancellation  SubscriptionStatus = "scheduled_for_cancellation"
	StatusCanceled                  SubscriptionStatus = "canceled"
)

// IsUsable returns true for statuses that should allow continued service.
func (s SubscriptionStatus) IsUsable() bool {
	switch s {
	case StatusActive, StatusTrialing, StatusScheduledForCancellation:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

// LicenseRequest is the payload sent to POST /v1/licensing/resolve.
type LicenseRequest struct {
	TenantID       string   `json:"tenant_id"`
	SubscriptionID string   `json:"subscription_id"`
	ServerID       string   `json:"server_id"`
	Features       []string `json:"features"`
}

// LicenseResponse is the reply from POST /v1/licensing/resolve.
type LicenseResponse struct {
	AllowedFeatures []string  `json:"allowed_features"`
	Status          string    `json:"status"` // active, trialing, paused, canceled
	Valid           bool      `json:"valid"`
	ExpiresAt       time.Time `json:"expires_at,omitempty"`
}

// BillingEvent is the payload sent to POST /v1/billing/events.
type BillingEvent struct {
	Type     string         `json:"type"` // server.startup, license.check, feature.usage, error
	TenantID string         `json:"tenant_id"`
	ServerID string         `json:"server_id"`
	Details  map[string]any `json:"details,omitempty"`
}

// TenantInfo is returned by GET /v1/tenants/{id}.
type TenantInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// SubscriptionInfo is returned by GET /v1/subscriptions/{id}.
type SubscriptionInfo struct {
	ID       string             `json:"id"`
	TenantID string             `json:"tenant_id"`
	Status   SubscriptionStatus `json:"status"`
	PlanID   string             `json:"plan_id"`
}

// authResponse is returned by POST /v1/auth/login.
type authResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// apiErrorResponse is the ValidonX error envelope.
type apiErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client communicates with the ValidonX licensing API.
type Client struct {
	baseURL    string
	serviceKey string
	tenantID   string
	subscriptionID string
	serverID   string
	// licenseKey is the path-1 cryptographic license string. Only used
	// by CheckLicensePath1; goes away when path-2 ships.
	licenseKey string
	httpClient *http.Client
	logger     *slog.Logger

	mu        sync.RWMutex
	token     string    // cached auth token
	tokenExp  time.Time // token expiry
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

// Authenticate calls POST /v1/auth/login with the service key and caches
// the returned token for subsequent API calls.
func (c *Client) Authenticate(ctx context.Context) error {
	if c == nil {
		return nil
	}

	payload := map[string]string{
		"service_key": c.serviceKey,
	}

	var resp authResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/auth/login", payload, &resp, false); err != nil {
		c.logger.Error("validonx authentication failed", "error", err)
		return fmt.Errorf("%s: %w", ErrAuthFailed, err)
	}

	c.mu.Lock()
	c.token = resp.Token
	c.tokenExp = resp.ExpiresAt
	c.mu.Unlock()

	c.logger.Info("validonx authentication successful", "expires_at", resp.ExpiresAt)
	return nil
}

// ResolveTenant calls GET /v1/tenants/{id} and returns tenant information.
func (c *Client) ResolveTenant(ctx context.Context, tenantID string) (*TenantInfo, error) {
	if c == nil {
		return nil, fmt.Errorf("validonx client not configured")
	}

	var resp TenantInfo
	if err := c.doJSON(ctx, http.MethodGet, "/v1/tenants/"+tenantID, nil, &resp, true); err != nil {
		return nil, fmt.Errorf("resolve tenant %s: %w", tenantID, err)
	}
	return &resp, nil
}

// ResolveSubscription calls GET /v1/subscriptions/{id} and returns subscription information.
func (c *Client) ResolveSubscription(ctx context.Context, subscriptionID string) (*SubscriptionInfo, error) {
	if c == nil {
		return nil, fmt.Errorf("validonx client not configured")
	}

	var resp SubscriptionInfo
	if err := c.doJSON(ctx, http.MethodGet, "/v1/subscriptions/"+subscriptionID, nil, &resp, true); err != nil {
		return nil, fmt.Errorf("resolve subscription %s: %w", subscriptionID, err)
	}
	return &resp, nil
}

// ResolveLicense calls POST /v1/licensing/resolve to check license entitlements.
func (c *Client) ResolveLicense(ctx context.Context, req LicenseRequest) (*LicenseResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("validonx client not configured")
	}

	var resp LicenseResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/licensing/resolve", req, &resp, true); err != nil {
		return nil, fmt.Errorf("%s: %w", ErrLicensingFailed, err)
	}
	return &resp, nil
}

// LogBillingEvent calls POST /v1/billing/events to record a billing event.
// Errors are logged but not returned — billing event logging must not block
// the mail server's operation.
func (c *Client) LogBillingEvent(ctx context.Context, event BillingEvent) error {
	if c == nil {
		return nil
	}

	if err := c.doJSON(ctx, http.MethodPost, "/v1/billing/events", event, nil, true); err != nil {
		c.logger.Warn("failed to log billing event", "type", event.Type, "error", err)
		return fmt.Errorf("log billing event: %w", err)
	}
	return nil
}

// CheckLicense is a convenience method that builds a LicenseRequest from the
// client's configured identifiers and resolves the license.
func (c *Client) CheckLicense(ctx context.Context, features []string) (*LicenseResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("validonx client not configured")
	}

	return c.ResolveLicense(ctx, LicenseRequest{
		TenantID:       c.tenantID,
		SubscriptionID: c.subscriptionID,
		ServerID:       c.serverID,
		Features:       features,
	})
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

// ensureAuth re-authenticates if the cached token is missing or about to expire.
func (c *Client) ensureAuth(ctx context.Context) error {
	c.mu.RLock()
	valid := c.token != "" && time.Now().Before(c.tokenExp.Add(-1*time.Minute))
	c.mu.RUnlock()

	if valid {
		return nil
	}
	return c.Authenticate(ctx)
}

// getToken returns the current cached auth token.
func (c *Client) getToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

// doJSON performs an HTTP request with JSON body/response handling.
// If auth is true, it ensures a valid token and includes the Authorization header.
func (c *Client) doJSON(ctx context.Context, method, path string, body any, dest any, auth bool) error {
	if auth {
		if err := c.ensureAuth(ctx); err != nil {
			return err
		}
	}

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

	if auth {
		req.Header.Set("Authorization", "Bearer "+c.getToken())
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
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Code != "" {
			return fmt.Errorf("%s: %s (HTTP %d)", errResp.Code, errResp.Message, resp.StatusCode)
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
