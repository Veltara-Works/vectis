package orchestrator

import "testing"

func TestIsLocalImageRef(t *testing.T) {
	tests := []struct {
		name  string
		image string
		local bool
	}{
		{"empty string", "", true},
		{"bare name no tag", "postgres", true},
		{"bare name with dev tag", "vectis-api:dev", true},
		{"bare name with hub-style tag", "postgres:17-alpine", true},
		{"library namespace", "library/postgres:17", false},
		{"ghcr.io reference", "ghcr.io/veltara-works/vectis-api:latest", false},
		{"docker.io reference", "docker.io/library/postgres:17-alpine", false},
		{"quay.io reference", "quay.io/coreos/etcd:v3.5", false},
		{"localhost registry", "localhost:5000/myapp:1.0", false},
		{"localhost no port", "localhost/myapp:1.0", false},
		{"private registry with port", "registry.example.com:5000/app:1", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isLocalImageRef(tc.image)
			if got != tc.local {
				t.Errorf("isLocalImageRef(%q) = %v, want %v", tc.image, got, tc.local)
			}
		})
	}
}
