package orchestrator

import (
	"encoding/json"
	"testing"
	"time"
)

// TestPlan_ClientEnvelopeRoundTrip guards against the class of bug tracked in
// deferred-items.md §10 blocker #1 (rc25): the API HTTP client and the
// orchestrator server previously defined independent structs with diverged
// JSON tags, so real drift was silently serialised as an empty plan and the
// UI reported "up to date" on boxes that were several releases behind.
//
// If anyone reintroduces a separate response struct with different JSON tags,
// this test will fail because one of the fields won't survive the round-trip.
func TestPlan_ClientEnvelopeRoundTrip(t *testing.T) {
	original := Plan{
		ID:               "01939e00-0000-7000-8000-000000000001",
		CreatedAt:        time.Date(2026, 4, 22, 9, 0, 0, 0, time.UTC),
		ConfigHash:       "deadbeef",
		BaselineVersions: map[string]string{"api": "v0.1.0-rc21", "postfix": "v0.1.0-rc21"},
		Changes: []PlanChange{
			{
				Service:  "api",
				Type:     "update",
				OldImage: "ghcr.io/veltara-works/vectis-api:v0.1.0-rc21",
				NewImage: "ghcr.io/veltara-works/vectis-api:v0.1.0-rc24",
			},
			{
				Service: "postfix",
				Type:    "config",
				Detail:  "regenerate main.cf",
			},
		},
		MigrationsUp: 2,
		ReleaseTag:   "v0.1.0-rc24",
		Warnings:     []string{"release channel unavailable: network timeout"},
	}

	// Marshal the wire shape that server.go:handlePlan emits.
	wire, err := json.Marshal(map[string]any{
		"state": "idle",
		"data":  map[string]any{"plan": original},
	})
	if err != nil {
		t.Fatalf("marshal server envelope: %v", err)
	}

	// Unmarshal via the client's envelope type.
	var env planEnvelope
	if err := json.Unmarshal(wire, &env); err != nil {
		t.Fatalf("unmarshal client envelope: %v", err)
	}
	got := env.Data.Plan

	if got.ID != original.ID {
		t.Errorf("ID drift: want %q got %q", original.ID, got.ID)
	}
	if got.ConfigHash != original.ConfigHash {
		t.Errorf("ConfigHash drift: want %q got %q", original.ConfigHash, got.ConfigHash)
	}
	if got.MigrationsUp != original.MigrationsUp {
		t.Errorf("MigrationsUp drift: want %d got %d", original.MigrationsUp, got.MigrationsUp)
	}
	if len(got.Changes) != len(original.Changes) {
		t.Fatalf("Changes length drift: want %d got %d — this is the rc25 blocker-1 signature", len(original.Changes), len(got.Changes))
	}
	for i, want := range original.Changes {
		if got.Changes[i] != want {
			t.Errorf("Changes[%d] drift: want %+v got %+v", i, want, got.Changes[i])
		}
	}
	if len(got.BaselineVersions) != len(original.BaselineVersions) {
		t.Errorf("BaselineVersions length drift: want %d got %d", len(original.BaselineVersions), len(got.BaselineVersions))
	}
	if got.ReleaseTag != original.ReleaseTag {
		t.Errorf("ReleaseTag drift: want %q got %q", original.ReleaseTag, got.ReleaseTag)
	}
	if len(got.Warnings) != len(original.Warnings) || (len(got.Warnings) > 0 && got.Warnings[0] != original.Warnings[0]) {
		t.Errorf("Warnings drift: want %v got %v", original.Warnings, got.Warnings)
	}
}

// TestPlanChange_JSONTagStability pins the wire field names so a future
// refactor renaming Go fields without thinking about the JSON contract will
// fail the test instead of silently breaking the UI.
func TestPlanChange_JSONTagStability(t *testing.T) {
	c := PlanChange{Service: "api", Type: "update", OldImage: "old", NewImage: "new", Detail: "d"}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"service":"api","type":"update","old_image":"old","new_image":"new","detail":"d"}`
	if string(b) != want {
		t.Errorf("PlanChange JSON drift:\n  want %s\n  got  %s", want, string(b))
	}
}
