package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client communicates with the orchestrator's internal HTTP API.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient creates a new orchestrator API client.
// baseURL is typically http://orchestrator:8081 (from Docker) or http://localhost:8081 (from host).
// token is the bearer token from secrets.yaml (orchestrator.token).
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// --- Response types ---

// PlanResult contains the output of an update plan operation.
type PlanResult struct {
	ID               string           `json:"id"`
	CreatedAt        time.Time        `json:"created_at"`
	ContainerChanges []ContainerDiff  `json:"container_changes,omitempty"`
	Migrations       []MigrationInfo  `json:"migrations,omitempty"`
	ConfigChanges    []string         `json:"config_changes,omitempty"`
	Warnings         []string         `json:"warnings,omitempty"`
	NoUpdates        bool             `json:"no_updates"`
}

// ContainerDiff describes a version change for a single container image.
type ContainerDiff struct {
	Service    string `json:"service"`
	CurrentTag string `json:"current_tag"`
	NewTag     string `json:"new_tag"`
}

// MigrationInfo describes a pending database migration.
type MigrationInfo struct {
	Name        string `json:"name"`
	Destructive bool   `json:"destructive"`
}

// ApplyResult contains the output of an update apply operation.
type ApplyResult struct {
	Status   string         `json:"status"` // "running", "success", "failed", "rolled_back", "rollback_failed"
	Steps    []ApplyStep    `json:"steps,omitempty"`
	Error    string         `json:"error,omitempty"`
	Rollback *RollbackInfo  `json:"rollback,omitempty"`
}

// ApplyStep describes one step in the apply pipeline.
type ApplyStep struct {
	Name     string `json:"name"`
	Status   string `json:"status"` // "pending", "running", "done", "failed"
	Detail   string `json:"detail,omitempty"`
	Duration string `json:"duration,omitempty"`
}

// RollbackInfo is included in ApplyResult when a rollback was triggered.
type RollbackInfo struct {
	Status string `json:"status"` // "success", "failed"
	Error  string `json:"error,omitempty"`
}

// RollbackResult contains the output of a manual rollback operation.
type RollbackResult struct {
	Status string `json:"status"` // "success", "failed"
	Error  string `json:"error,omitempty"`
}

// StatusResult contains the current orchestrator status.
type StatusResult struct {
	State       string       `json:"state"` // "idle", "planning", "applying", "rolling_back"
	CurrentStep string       `json:"current_step,omitempty"`
	PlanID      string       `json:"plan_id,omitempty"`
	Steps       []ApplyStep  `json:"steps,omitempty"`
	Error       string       `json:"error,omitempty"`
	LastApply   *time.Time   `json:"last_apply,omitempty"`
}

// --- API methods ---

// Plan requests the orchestrator to generate an update plan.
func (c *Client) Plan(ctx context.Context) (*PlanResult, error) {
	var result PlanResult
	if err := c.doJSON(ctx, http.MethodPost, "/internal/plan", &result); err != nil {
		return nil, fmt.Errorf("plan: %w", err)
	}
	return &result, nil
}

// Apply requests the orchestrator to execute the current plan.
// If force is true, the orchestrator will plan and apply in one step.
func (c *Client) Apply(ctx context.Context, force bool) (*ApplyResult, error) {
	path := "/internal/apply"
	if force {
		path += "?force=true"
	}
	var result ApplyResult
	if err := c.doJSON(ctx, http.MethodPost, path, &result); err != nil {
		return nil, fmt.Errorf("apply: %w", err)
	}
	return &result, nil
}

// Rollback requests the orchestrator to roll back to the last snapshot.
func (c *Client) Rollback(ctx context.Context) (*RollbackResult, error) {
	var result RollbackResult
	if err := c.doJSON(ctx, http.MethodPost, "/internal/rollback", &result); err != nil {
		return nil, fmt.Errorf("rollback: %w", err)
	}
	return &result, nil
}

// Status returns the current orchestrator state machine status.
func (c *Client) Status(ctx context.Context) (*StatusResult, error) {
	var result StatusResult
	if err := c.doJSON(ctx, http.MethodGet, "/internal/status", &result); err != nil {
		return nil, fmt.Errorf("status: %w", err)
	}
	return &result, nil
}

// Health performs a basic health check against the orchestrator.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/internal/health", nil)
	if err != nil {
		return fmt.Errorf("health: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("health: orchestrator unreachable: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health: orchestrator returned status %d", resp.StatusCode)
	}
	return nil
}

// --- Internal helpers ---

// apiErrorResponse represents an error envelope from the orchestrator.
type apiErrorResponse struct {
	Error string `json:"error"`
}

// doJSON performs an HTTP request and decodes the JSON response into dest.
func (c *Client) doJSON(ctx context.Context, method, path string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("orchestrator unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB max
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp apiErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("orchestrator error (%d): %s", resp.StatusCode, errResp.Error)
		}
		return fmt.Errorf("orchestrator error (%d): %s", resp.StatusCode, string(body))
	}

	if dest != nil && len(body) > 0 {
		if err := json.Unmarshal(body, dest); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}

	return nil
}
