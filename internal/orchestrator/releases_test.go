package orchestrator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchReleaseManifest_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"latest":"v0.1.0-rc24","released_at":"2026-04-22T08:00:00Z","channel":"rc"}`))
	}))
	defer srv.Close()

	m, err := fetchReleaseManifest(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Latest != "v0.1.0-rc24" {
		t.Errorf("Latest: want v0.1.0-rc24, got %q", m.Latest)
	}
	if m.Channel != "rc" {
		t.Errorf("Channel: want rc, got %q", m.Channel)
	}
	if m.ReleasedAt.IsZero() {
		t.Error("ReleasedAt should be populated")
	}
}

func TestFetchReleaseManifest_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	_, err := fetchReleaseManifest(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("expected error on 404, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention 404, got: %v", err)
	}
}

func TestFetchReleaseManifest_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not valid json at all"))
	}))
	defer srv.Close()

	_, err := fetchReleaseManifest(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
}

func TestFetchReleaseManifest_MissingLatest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"channel":"rc"}`))
	}))
	defer srv.Close()

	_, err := fetchReleaseManifest(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("expected error for missing latest field")
	}
	if !strings.Contains(err.Error(), "latest") {
		t.Errorf("error should mention `latest`, got: %v", err)
	}
}

func TestFetchReleaseManifest_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"latest":"v0.1.0-rc24"}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := fetchReleaseManifest(ctx, srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestRewriteReleaseTag(t *testing.T) {
	cases := []struct {
		name  string
		image string
		tag   string
		want  string
	}{
		{
			name:  "vectis-api gets retagged",
			image: "ghcr.io/veltara-works/vectis-api:v0.1.0-rc21",
			tag:   "v0.1.0-rc24",
			want:  "ghcr.io/veltara-works/vectis-api:v0.1.0-rc24",
		},
		{
			name:  "vectis-dovecot gets retagged",
			image: "ghcr.io/veltara-works/vectis-dovecot:v0.1.0-rc21",
			tag:   "v0.1.0-rc24",
			want:  "ghcr.io/veltara-works/vectis-dovecot:v0.1.0-rc24",
		},
		{
			name:  "postgres upstream image untouched",
			image: "postgres:17-alpine",
			tag:   "v0.1.0-rc24",
			want:  "postgres:17-alpine",
		},
		{
			name:  "traefik upstream image untouched",
			image: "traefik:v3.3",
			tag:   "v0.1.0-rc24",
			want:  "traefik:v3.3",
		},
		{
			name:  "acme.sh upstream image untouched",
			image: "neilpang/acme.sh:latest",
			tag:   "v0.1.0-rc24",
			want:  "neilpang/acme.sh:latest",
		},
		{
			name:  "vectis image without tag left alone",
			image: "ghcr.io/veltara-works/vectis-api",
			tag:   "v0.1.0-rc24",
			want:  "ghcr.io/veltara-works/vectis-api",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rewriteReleaseTag(tc.image, tc.tag)
			if got != tc.want {
				t.Errorf("\n  image: %s\n  tag:   %s\n  want:  %s\n  got:   %s", tc.image, tc.tag, tc.want, got)
			}
		})
	}
}
