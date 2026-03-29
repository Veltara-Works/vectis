package orchestrator

import "time"

// Operation records details of an in-flight or completed orchestrator operation.
type Operation struct {
	JobID        string     `json:"job_id"`
	Type         string     `json:"type"` // "plan", "apply", "rollback"
	State        State      `json:"state"`
	StartedAt    time.Time  `json:"started_at"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
	Error        string     `json:"error,omitempty"`
	SnapshotPath string     `json:"snapshot_path,omitempty"`
}

// StatusResponse is returned by the Status endpoint (Spec D.10).
type StatusResponse struct {
	State         State      `json:"state"`
	LastOperation *Operation `json:"last_operation,omitempty"`
}

// HealthResponse is returned by the Health endpoint (Spec D.10).
type HealthResponse struct {
	Healthy bool   `json:"healthy"`
	State   State  `json:"state"`
	Error   string `json:"error,omitempty"`
}
