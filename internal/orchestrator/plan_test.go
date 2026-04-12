package orchestrator

import (
	"testing"
	"time"
)

func TestPlan_IsEmpty(t *testing.T) {
	empty := &Plan{ID: "1", CreatedAt: time.Now()}
	if !empty.IsEmpty() {
		t.Error("plan with no changes and no migrations should be empty")
	}

	withChanges := &Plan{Changes: []PlanChange{{Service: "postfix", Type: "update"}}}
	if withChanges.IsEmpty() {
		t.Error("plan with changes should not be empty")
	}

	withMigrations := &Plan{MigrationsUp: 3}
	if withMigrations.IsEmpty() {
		t.Error("plan with migrations should not be empty")
	}
}

func TestPlan_IsStale_ConfigHashChanged(t *testing.T) {
	p := &Plan{
		ConfigHash:       "abc123",
		BaselineVersions: map[string]string{"postfix": "v1"},
	}

	if p.IsStale("abc123", map[string]string{"postfix": "v1"}) {
		t.Error("should not be stale when nothing changed")
	}

	if !p.IsStale("def456", map[string]string{"postfix": "v1"}) {
		t.Error("should be stale when config hash changed")
	}
}

func TestPlan_IsStale_VersionChanged(t *testing.T) {
	p := &Plan{
		ConfigHash:       "abc123",
		BaselineVersions: map[string]string{"postfix": "v1", "dovecot": "v2"},
	}

	if !p.IsStale("abc123", map[string]string{"postfix": "v1", "dovecot": "v3"}) {
		t.Error("should be stale when a container version changed")
	}
}

func TestPlan_IsStale_ExtraCurrentVersions(t *testing.T) {
	p := &Plan{
		ConfigHash:       "abc123",
		BaselineVersions: map[string]string{"postfix": "v1"},
	}

	if p.IsStale("abc123", map[string]string{"postfix": "v1", "rspamd": "v2"}) {
		t.Error("extra services in current should not make plan stale")
	}
}
