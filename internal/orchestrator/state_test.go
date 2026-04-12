package orchestrator

import (
	"testing"
	"time"
)

func TestCanPlan(t *testing.T) {
	tests := []struct {
		state State
		want  bool
	}{
		{StateIdle, true},
		{StateFailed, true},
		{StateCompleted, true},
		{StatePlanning, false},
		{StateValidating, false},
		{StateApplying, false},
		{StateRollingBack, false},
	}
	for _, tt := range tests {
		if got := tt.state.CanPlan(); got != tt.want {
			t.Errorf("State(%q).CanPlan() = %v, want %v", tt.state, got, tt.want)
		}
	}
}

func TestCanApply(t *testing.T) {
	tests := []struct {
		state State
		want  bool
	}{
		{StateIdle, true},
		{StateCompleted, true},
		{StateFailed, false},
		{StatePlanning, false},
		{StateValidating, false},
		{StateApplying, false},
		{StateRollingBack, false},
	}
	for _, tt := range tests {
		if got := tt.state.CanApply(); got != tt.want {
			t.Errorf("State(%q).CanApply() = %v, want %v", tt.state, got, tt.want)
		}
	}
}

func TestCanRollback(t *testing.T) {
	tests := []struct {
		state State
		want  bool
	}{
		{StateIdle, true},
		{StateFailed, true},
		{StateCompleted, true},
		{StatePlanning, false},
		{StateValidating, false},
		{StateApplying, false},
		{StateRollingBack, false},
	}
	for _, tt := range tests {
		if got := tt.state.CanRollback(); got != tt.want {
			t.Errorf("State(%q).CanRollback() = %v, want %v", tt.state, got, tt.want)
		}
	}
}

func TestValidTransitions_Completeness(t *testing.T) {
	allStates := []State{
		StateIdle, StatePlanning, StateValidating,
		StateApplying, StateRollingBack, StateFailed, StateCompleted,
	}
	for _, s := range allStates {
		if _, ok := ValidTransitions[s]; !ok {
			t.Errorf("state %q has no entry in ValidTransitions", s)
		}
	}
}

func TestValidTransitions_NoSelfTransition(t *testing.T) {
	for from, targets := range ValidTransitions {
		if targets[from] {
			t.Errorf("self-transition allowed: %s -> %s", from, from)
		}
	}
}

func TestValidTransitions_IdleReachable(t *testing.T) {
	canReachIdle := false
	for _, targets := range ValidTransitions {
		if targets[StateIdle] {
			canReachIdle = true
			break
		}
	}
	if !canReachIdle {
		t.Error("no state can transition to idle")
	}
}

func TestErrInvalidTransition_Error(t *testing.T) {
	err := &ErrInvalidTransition{From: StateIdle, To: StateApplying}
	msg := err.Error()
	if msg == "" {
		t.Fatal("expected non-empty error message")
	}

	errWithOp := &ErrInvalidTransition{From: StateIdle, To: StateApplying, Op: "apply"}
	msg = errWithOp.Error()
	if msg == "" {
		t.Fatal("expected non-empty error message with op")
	}
}

// --- Config tests ---

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ImagePullTimeout != 300*time.Second {
		t.Errorf("ImagePullTimeout = %v, want 300s", cfg.ImagePullTimeout)
	}
	if cfg.HealthCheckTimeout != 120*time.Second {
		t.Errorf("HealthCheckTimeout = %v, want 120s", cfg.HealthCheckTimeout)
	}
	if cfg.ApplyTimeout != 600*time.Second {
		t.Errorf("ApplyTimeout = %v, want 600s", cfg.ApplyTimeout)
	}
	if cfg.SnapshotDir != "/var/vectis/snapshots" {
		t.Errorf("SnapshotDir = %q", cfg.SnapshotDir)
	}
}

func TestServiceStopOrder_ReverseOfStart(t *testing.T) {
	stop := ServiceStopOrder()
	if len(stop) != len(ServiceStartOrder) {
		t.Fatalf("stop order length %d != start order length %d", len(stop), len(ServiceStartOrder))
	}
	n := len(stop)
	for i, s := range stop {
		if s != ServiceStartOrder[n-1-i] {
			t.Errorf("stop[%d] = %q, want %q", i, s, ServiceStartOrder[n-1-i])
		}
	}
}

func TestServiceStartOrder_PostgresFirst(t *testing.T) {
	if ServiceStartOrder[0] != "postgres" {
		t.Errorf("first service should be postgres, got %q", ServiceStartOrder[0])
	}
}

func TestServiceHealthTimeouts_AllServicesHaveTimeout(t *testing.T) {
	for _, svc := range ServiceStartOrder {
		if _, ok := ServiceHealthTimeouts[svc]; !ok {
			t.Errorf("service %q missing from ServiceHealthTimeouts", svc)
		}
	}
}
