package orchestrator

import "testing"

func TestImageHasFloatingTag(t *testing.T) {
	tests := []struct {
		name string
		img  string
		want bool
	}{
		{"explicit version pin", "ghcr.io/veltara-works/vectis-api:v0.1.5", false},
		{"explicit rc pin", "ghcr.io/veltara-works/vectis-api:v0.1.6-rc1", false},
		{"latest is floating", "ghcr.io/veltara-works/vectis-api:latest", true},
		{"untagged defaults to latest", "ghcr.io/veltara-works/vectis-api", true},
		{"local dev image with version", "vectis-api:dev", false},
		{"local dev with no tag", "vectis-api", true},
		{"empty string is benign (skip)", "", false},
		{"docker hub with namespace and pin", "library/postgres:16", false},
		{"port in registry host", "localhost:5000/vectis-api:v1.2.3", false},
		{"port in registry host with latest", "localhost:5000/vectis-api:latest", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := imageHasFloatingTag(tc.img); got != tc.want {
				t.Errorf("imageHasFloatingTag(%q) = %v, want %v", tc.img, got, tc.want)
			}
		})
	}
}
