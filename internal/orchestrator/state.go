package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valkey-io/valkey-go"

	"github.com/Veltara-Works/vectis/internal/types"
)

// Orchestrator states per Spec D.2.
type State string

const (
	StateIdle        State = "idle"
	StatePlanning    State = "planning"
	StateValidating  State = "validating"
	StateApplying    State = "applying"
	StateRollingBack State = "rolling_back"
	StateFailed      State = "failed"
	StateCompleted   State = "completed"
)

// ValidTransitions defines the allowed state transitions per Spec D.3.
// Map key is the "from" state; value is a set of valid "to" states.
var ValidTransitions = map[State]map[State]bool{
	StateIdle: {
		StatePlanning:    true,
		StateValidating:  true,
		StateRollingBack: true,
	},
	StatePlanning: {
		StateIdle:   true,
		StateFailed: true,
	},
	StateValidating: {
		StateApplying: true,
		StateFailed:   true,
	},
	StateApplying: {
		StateIdle:        true,
		StateRollingBack: true,
		StateFailed:      true,
	},
	StateRollingBack: {
		StateIdle:   true,
		StateFailed: true,
	},
	StateFailed: {
		StateRollingBack: true,
		StatePlanning:    true,
	},
	StateCompleted: {
		StatePlanning:    true,
		StateValidating:  true,
		StateRollingBack: true,
	},
}

// ErrInvalidTransition is returned when a state transition is not allowed.
type ErrInvalidTransition struct {
	From State
	To   State
	Op   string
}

func (e *ErrInvalidTransition) Error() string {
	if e.Op != "" {
		return fmt.Sprintf("operation %q not allowed in state %q", e.Op, e.From)
	}
	return fmt.Sprintf("invalid state transition: %s -> %s", e.From, e.To)
}

// CanPlan reports whether a Plan operation is allowed in this state.
func (s State) CanPlan() bool {
	return s == StateIdle || s == StateFailed || s == StateCompleted
}

// CanApply reports whether an Apply operation is allowed in this state.
func (s State) CanApply() bool {
	return s == StateIdle || s == StateCompleted
}

// CanRollback reports whether a Rollback operation is allowed in this state.
func (s State) CanRollback() bool {
	return s == StateIdle || s == StateFailed || s == StateCompleted
}

// StateMachine manages the orchestrator's lifecycle state with thread safety.
// State is dual-stored in memory (fast) and Valkey (queryable by the API)
// with operations persisted to Postgres orchestrator_history.
type StateMachine struct {
	mu     sync.RWMutex
	state  State
	db     *pgxpool.Pool
	vk     valkey.Client
	logger *slog.Logger
}

// NewStateMachine creates a StateMachine starting in the idle state.
// On construction it checks Postgres for incomplete operations from a previous
// crash and recovers accordingly (Spec D.4 crash recovery).
func NewStateMachine(ctx context.Context, db *pgxpool.Pool, vk valkey.Client, logger *slog.Logger) (*StateMachine, error) {
	sm := &StateMachine{
		state:  StateIdle,
		db:     db,
		vk:     vk,
		logger: logger,
	}

	if err := sm.recoverState(ctx); err != nil {
		return nil, fmt.Errorf("recover orchestrator state: %w", err)
	}

	// Sync initial state to Valkey.
	if err := sm.syncToValkey(ctx); err != nil {
		return nil, fmt.Errorf("sync initial state to valkey: %w", err)
	}

	logger.Info("state machine initialised", "state", string(sm.state))
	return sm, nil
}

// State returns the current state (thread-safe).
func (sm *StateMachine) State() State {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.state
}

// Transition validates and performs a state transition.
// Returns ErrInvalidTransition if the transition is not allowed per Spec D.3.
func (sm *StateMachine) Transition(ctx context.Context, to State) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	from := sm.state

	targets, ok := ValidTransitions[from]
	if !ok || !targets[to] {
		sm.logger.Warn("rejected state transition",
			"from", string(from),
			"to", string(to),
		)
		return &ErrInvalidTransition{From: from, To: to}
	}

	sm.state = to
	sm.logger.Info("state transition",
		"from", string(from),
		"to", string(to),
	)

	if err := sm.syncToValkey(ctx); err != nil {
		sm.logger.Error("failed to sync state to valkey", "error", err)
		// Non-fatal: in-memory state is authoritative for the orchestrator process.
	}

	return nil
}

// SetState sets the state without transition validation (used for crash recovery
// and internal operations where the transition may not follow normal flow).
func (sm *StateMachine) SetState(ctx context.Context, s State) {
	sm.mu.Lock()
	sm.state = s
	sm.mu.Unlock()

	if err := sm.syncToValkey(ctx); err != nil {
		sm.logger.Error("failed to sync state to valkey", "error", err)
	}
}

// RecordOperation inserts a row into orchestrator_history and returns its ID.
func (sm *StateMachine) RecordOperation(ctx context.Context, action, status, configHash string, planSummary map[string]any, containerVersions map[string]string) (string, error) {
	id := types.NewUUIDv7()

	var planJSON, versionsJSON []byte
	var err error

	if planSummary != nil {
		planJSON, err = json.Marshal(planSummary)
		if err != nil {
			return "", fmt.Errorf("marshal plan summary: %w", err)
		}
	}

	if containerVersions != nil {
		versionsJSON, err = json.Marshal(containerVersions)
		if err != nil {
			return "", fmt.Errorf("marshal container versions: %w", err)
		}
	}

	_, err = sm.db.Exec(ctx,
		`INSERT INTO orchestrator_history (id, action, status, config_hash, plan_summary, container_versions, started_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, action, status, configHash, planJSON, versionsJSON, time.Now().UTC(),
	)
	if err != nil {
		return "", fmt.Errorf("insert orchestrator_history: %w", err)
	}

	sm.logger.Info("recorded operation",
		"id", id,
		"action", action,
		"status", status,
	)

	return id, nil
}

// CompleteOperation updates an orchestrator_history row to its final status.
func (sm *StateMachine) CompleteOperation(ctx context.Context, operationID, status, snapshotPath, errorMsg string) error {
	_, err := sm.db.Exec(ctx,
		`UPDATE orchestrator_history
		 SET status = $1, snapshot_path = $2, error_message = $3, completed_at = $4
		 WHERE id = $5`,
		status, snapshotPath, errorMsg, time.Now().UTC(), operationID,
	)
	if err != nil {
		return fmt.Errorf("update orchestrator_history: %w", err)
	}
	return nil
}

// LastOperation returns the most recent orchestrator_history entry.
func (sm *StateMachine) LastOperation(ctx context.Context) (*OperationRecord, error) {
	row := sm.db.QueryRow(ctx,
		`SELECT id, action, status, config_hash, plan_summary, snapshot_path,
		        container_versions, error_message, started_at, completed_at
		 FROM orchestrator_history
		 ORDER BY started_at DESC
		 LIMIT 1`,
	)

	var rec OperationRecord
	var planJSON, versionsJSON []byte
	err := row.Scan(
		&rec.ID, &rec.Action, &rec.Status, &rec.ConfigHash,
		&planJSON, &rec.SnapshotPath, &versionsJSON,
		&rec.ErrorMessage, &rec.StartedAt, &rec.CompletedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("query last operation: %w", err)
	}

	if planJSON != nil {
		if err := json.Unmarshal(planJSON, &rec.PlanSummary); err != nil {
			return nil, fmt.Errorf("unmarshal plan summary: %w", err)
		}
	}
	if versionsJSON != nil {
		if err := json.Unmarshal(versionsJSON, &rec.ContainerVersions); err != nil {
			return nil, fmt.Errorf("unmarshal container versions: %w", err)
		}
	}

	return &rec, nil
}

// OperationRecord represents a row from orchestrator_history.
type OperationRecord struct {
	ID                string            `json:"id"`
	Action            string            `json:"action"`
	Status            string            `json:"status"`
	ConfigHash        string            `json:"config_hash"`
	PlanSummary       map[string]any    `json:"plan_summary,omitempty"`
	SnapshotPath      *string           `json:"snapshot_path,omitempty"`
	ContainerVersions map[string]string `json:"container_versions,omitempty"`
	ErrorMessage      *string           `json:"error_message,omitempty"`
	StartedAt         time.Time         `json:"started_at"`
	CompletedAt       *time.Time        `json:"completed_at,omitempty"`
}

// recoverState checks orchestrator_history for incomplete operations from a
// previous crash and adjusts the initial state accordingly (Spec D.4).
func (sm *StateMachine) recoverState(ctx context.Context) error {
	var status string
	err := sm.db.QueryRow(ctx,
		`SELECT status FROM orchestrator_history ORDER BY started_at DESC LIMIT 1`,
	).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		// No rows = fresh installation -> idle.
		sm.logger.Info("no prior operations found, starting in idle state")
		sm.state = StateIdle
		return nil
	}
	if err != nil {
		// A real query error (connection blip, timeout, permission) must NOT be
		// silently treated as "fresh install" — that would clear the crash gate
		// (CanApply/CanPlan return true) on a half-upgraded stack. Fail loud:
		// startup aborts and the operator/Docker restart-policy retries, which
		// is the conservative choice for crash recovery (Spec D.4).
		return fmt.Errorf("query last orchestrator operation for crash recovery: %w", err)
	}

	switch status {
	case "running":
		// Crashed mid-operation -> mark as failed, enter failed state.
		sm.logger.Warn("detected incomplete operation from previous run, marking as failed")
		_, markErr := sm.db.Exec(ctx,
			`UPDATE orchestrator_history
			 SET status = 'failed', error_message = 'process crashed mid-operation', completed_at = $1
			 WHERE status = 'running' AND completed_at IS NULL`,
			time.Now().UTC(),
		)
		if markErr != nil {
			return fmt.Errorf("mark crashed operation as failed: %w", markErr)
		}
		sm.state = StateFailed
	case "failed":
		sm.state = StateFailed
	default:
		// completed, rolled_back, etc. -> idle.
		sm.state = StateIdle
	}

	sm.logger.Info("recovered state from history", "last_status", status, "state", string(sm.state))
	return nil
}

// syncToValkey writes the current state to Valkey for fast queries by the API.
func (sm *StateMachine) syncToValkey(ctx context.Context) error {
	cmd := sm.vk.B().Set().Key("orchestrator:state").Value(string(sm.state)).Build()
	return sm.vk.Do(ctx, cmd).Error()
}
