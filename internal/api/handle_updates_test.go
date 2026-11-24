package api

import (
	"testing"

	"github.com/Veltara-Works/vectis/internal/updatecheck"
)

func TestReconcileWithRunning(t *testing.T) {
	cases := []struct {
		name, running, latest string
		stored, want          bool
	}{
		{"still behind", "v0.1.65", "v0.1.66", true, true},
		{"updated to it since the check", "v0.1.66", "v0.1.66", true, false},
		{"updated past it", "v0.1.67", "v0.1.66", true, false},
		{"nothing stored as available", "v0.1.65", "v0.1.66", false, false},
		{"dev build leaves it alone", "dev", "v0.1.66", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reconcileWithRunning(updatecheck.State{Latest: tc.latest, UpdateAvailable: tc.stored}, tc.running)
			if got.UpdateAvailable != tc.want {
				t.Errorf("UpdateAvailable = %v, want %v", got.UpdateAvailable, tc.want)
			}
		})
	}
}
