package orchestrator

import (
	"testing"
	"time"
)

// TestLastOperationReturnsCopy is the regression guard for the data-race audit
// finding: LastOperation()/Status() used to return o.lastOp directly, which the
// Apply goroutine then mutated (State/EndedAt/SnapshotPath) while handlers
// json-marshalled it with no lock held. The methods must hand out an immutable
// snapshot instead.
func TestLastOperationReturnsCopy(t *testing.T) {
	end := time.Now().UTC()
	o := &Orchestrator{lastOp: &Operation{
		JobID:        "j1",
		Type:         "apply",
		State:        StateApplying,
		EndedAt:      &end,
		SnapshotPath: "/snap",
	}}

	got := o.LastOperation()
	if got == nil {
		t.Fatal("LastOperation returned nil for a set operation")
	}
	if got == o.lastOp {
		t.Fatal("LastOperation returned the shared pointer, not a copy (data race)")
	}

	// Simulate the Apply goroutine mutating the live struct after the caller has
	// taken its snapshot. The snapshot must be unaffected.
	o.lastOp.State = StateIdle
	o.lastOp.SnapshotPath = "/changed"
	if got.State != StateApplying || got.SnapshotPath != "/snap" {
		t.Fatalf("snapshot was mutated by later writes to the live op: %+v", got)
	}
}

func TestLastOperationNil(t *testing.T) {
	o := &Orchestrator{}
	if got := o.LastOperation(); got != nil {
		t.Fatalf("expected nil for no operation, got %+v", got)
	}
}
