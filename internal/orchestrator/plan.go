package orchestrator

import "time"

// Plan describes the diff between the current and desired system state.
// Computed by Plan() and consumed by Apply(). Becomes stale if the system
// state changes between plan and apply (Spec D.9).
type Plan struct {
	ID                string            `json:"id"`
	CreatedAt         time.Time         `json:"created_at"`
	ConfigHash        string            `json:"config_hash"`
	BaselineVersions  map[string]string `json:"baseline_versions"`
	Changes           []PlanChange      `json:"changes"`
	MigrationsUp      int               `json:"migrations_up"`
}

// PlanChange describes a single change in a plan.
type PlanChange struct {
	Service  string `json:"service"`
	Type     string `json:"type"` // "create", "update", "remove", "config", "migrate"
	OldImage string `json:"old_image,omitempty"`
	NewImage string `json:"new_image,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// IsEmpty reports whether the plan contains no changes.
func (p *Plan) IsEmpty() bool {
	return len(p.Changes) == 0 && p.MigrationsUp == 0
}

// IsStale checks whether the plan's baseline still matches the current system
// state. Returns true if the config hash or container versions have changed
// since the plan was computed (Spec D.9).
func (p *Plan) IsStale(currentConfigHash string, currentVersions map[string]string) bool {
	if p.ConfigHash != currentConfigHash {
		return true
	}
	for svc, ver := range p.BaselineVersions {
		if currentVersions[svc] != ver {
			return true
		}
	}
	return false
}
