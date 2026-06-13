package orchestrator

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Veltara-Works/vectis/internal/engine"
)

// Client communicates with the orchestrator's internal HTTP API.
type Client struct {
	baseURL string
	token   string // bearer token (used when mTLS is not configured)
	useMTLS bool
	http    *http.Client
}

// NewClient creates a new orchestrator API client using bearer token auth.
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

// NewMTLSClient creates a new orchestrator API client using mutual TLS.
// The baseURL should use https:// when mTLS is enabled.
func NewMTLSClient(baseURL string, tlsConfig *tls.Config) *Client {
	return &Client{
		baseURL: baseURL,
		useMTLS: true,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}
}

// --- Response types ---

// The Plan type is defined in plan.go and is the single canonical shape of a
// plan response — the orchestrator server, the API HTTP client, the CLI, and
// the admin UI all consume it directly. Previously a duplicate PlanResult
// struct lived here with mismatched JSON tags, which silently ate drift
// detection end-to-end (see deferred-items.md §10).

// ApplyResult contains the output of an update apply operation.
type ApplyResult struct {
	Status   string        `json:"status"` // "running", "success", "failed", "rolled_back", "rollback_failed"
	JobID    string        `json:"job_id,omitempty"`
	Steps    []ApplyStep   `json:"steps,omitempty"`
	Error    string        `json:"error,omitempty"`
	Rollback *RollbackInfo `json:"rollback,omitempty"`
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
	Status string `json:"status"` // "running", "success", "failed"
	JobID  string `json:"job_id,omitempty"`
	Error  string `json:"error,omitempty"`
}

// StatusResult contains the current orchestrator status.
type StatusResult struct {
	State       string      `json:"state"` // "idle", "planning", "applying", "rolling_back"
	CurrentStep string      `json:"current_step,omitempty"`
	PlanID      string      `json:"plan_id,omitempty"`
	Steps       []ApplyStep `json:"steps,omitempty"`
	Error       string      `json:"error,omitempty"`
	LastApply   *time.Time  `json:"last_apply,omitempty"`
	// SelfUpgradeUntil is set during the rc36+ orchestrator self-replace
	// window (the ~30s between Apply recording "completed" and the helper
	// container actually firing `docker compose up -d orchestrator`). The UI
	// uses this to render a countdown banner so the user doesn't think Apply
	// has stalled. Nil when no self-replacement is pending.
	SelfUpgradeUntil *time.Time `json:"self_upgrade_until,omitempty"`
}

// --- API methods ---

// The orchestrator server wraps every success response as {state, data: {...}}
// (see internal/orchestrator/server.go). We unmarshal into these envelope
// structs and copy the inner payload out.

type planEnvelope struct {
	State string `json:"state"`
	Data  struct {
		Plan Plan `json:"plan"`
	} `json:"data"`
}

type jobEnvelope struct {
	State string `json:"state"`
	Data  struct {
		JobID string `json:"job_id"`
	} `json:"data"`
}

type statusEnvelope struct {
	State            string     `json:"state"`
	SelfUpgradeUntil *time.Time `json:"self_upgrade_until,omitempty"`
	Data             struct {
		LastOperation *lastOperation `json:"last_operation,omitempty"`
	} `json:"data"`
}

type lastOperation struct {
	JobID        string     `json:"job_id,omitempty"`
	Type         string     `json:"type,omitempty"`
	State        string     `json:"state,omitempty"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
	SnapshotPath string     `json:"snapshot_path,omitempty"`
	Error        string     `json:"error,omitempty"`
}

// Plan requests the orchestrator to generate an update plan.
func (c *Client) Plan(ctx context.Context) (*Plan, error) {
	var env planEnvelope
	if err := c.doJSON(ctx, http.MethodPost, "/internal/plan", &env); err != nil {
		return nil, fmt.Errorf("plan: %w", err)
	}
	result := env.Data.Plan
	return &result, nil
}

// Apply requests the orchestrator to execute the current plan. Apply is
// asynchronous: the orchestrator returns a job_id immediately and continues
// the work in the background. The caller should poll /internal/status to
// observe completion.
//
// If force is true, the orchestrator will plan and apply in one step.
func (c *Client) Apply(ctx context.Context, force bool) (*ApplyResult, error) {
	path := "/internal/apply"
	if force {
		path += "?force=true"
	}
	var env jobEnvelope
	if err := c.doJSON(ctx, http.MethodPost, path, &env); err != nil {
		return nil, fmt.Errorf("apply: %w", err)
	}
	// Synthesise an ApplyResult. The actual apply runs asynchronously; the
	// returned status is "running" until /status reports idle or failed.
	return &ApplyResult{Status: "running", JobID: env.Data.JobID}, nil
}

// Rollback requests the orchestrator to roll back to the last snapshot.
// Rollback is asynchronous; the returned RollbackResult carries the job_id.
func (c *Client) Rollback(ctx context.Context) (*RollbackResult, error) {
	var env jobEnvelope
	if err := c.doJSON(ctx, http.MethodPost, "/internal/rollback", &env); err != nil {
		return nil, fmt.Errorf("rollback: %w", err)
	}
	return &RollbackResult{Status: "running", JobID: env.Data.JobID}, nil
}

// reloadEnvelope is the response shape for /internal/reload.
type reloadEnvelope struct {
	Data struct {
		Results []engine.ReloadResult `json:"results"`
	} `json:"data"`
}

// Reload asks the orchestrator to run service reload/restart actions on the
// caller's behalf. The api container uses this because it has no docker socket
// of its own — only the orchestrator mounts /var/run/docker.sock. Reload is
// best-effort and synchronous (it does not go through the apply state machine).
func (c *Client) Reload(ctx context.Context, actions []engine.ServiceAction) ([]engine.ReloadResult, error) {
	body, err := json.Marshal(map[string]any{"actions": actions})
	if err != nil {
		return nil, fmt.Errorf("reload: marshal: %w", err)
	}
	var env reloadEnvelope
	if err := c.doJSONWithBody(ctx, http.MethodPost, "/internal/reload", bytes.NewReader(body), &env); err != nil {
		return nil, fmt.Errorf("reload: %w", err)
	}
	return env.Data.Results, nil
}

// Status returns the current orchestrator state machine status.
func (c *Client) Status(ctx context.Context) (*StatusResult, error) {
	var env statusEnvelope
	if err := c.doJSON(ctx, http.MethodGet, "/internal/status", &env); err != nil {
		return nil, fmt.Errorf("status: %w", err)
	}
	result := StatusResult{
		State:            env.State,
		SelfUpgradeUntil: env.SelfUpgradeUntil,
	}
	if env.Data.LastOperation != nil {
		result.CurrentStep = env.Data.LastOperation.Type
		result.Error = env.Data.LastOperation.Error
	}
	return &result, nil
}

// Health performs a basic health check against the orchestrator.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/internal/health", nil)
	if err != nil {
		return fmt.Errorf("health: %w", err)
	}
	c.setAuth(req)

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

// setAuth applies the appropriate authentication to the request.
// With mTLS, the client cert is presented at the TLS layer — no header needed.
// Without mTLS, the bearer token is set in the Authorization header.
func (c *Client) setAuth(req *http.Request) {
	if !c.useMTLS && c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

// doJSON performs a body-less HTTP request and decodes the JSON response into dest.
func (c *Client) doJSON(ctx context.Context, method, path string, dest any) error {
	return c.doJSONWithBody(ctx, method, path, nil, dest)
}

// doJSONWithBody performs an HTTP request with an optional request body and
// decodes the JSON response into dest.
func (c *Client) doJSONWithBody(ctx context.Context, method, path string, reqBody io.Reader, dest any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return err
	}
	c.setAuth(req)
	req.Header.Set("Accept", "application/json")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

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
