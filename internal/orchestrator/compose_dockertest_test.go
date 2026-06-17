//go:build dockertest

// Docker-integration tests for DockerManager's COMPOSE LIFECYCLE. Where
// docker_dockertest_test.go covers the single-container inspect/health/network
// parsers, this file drives the full `docker compose …` surface the orchestrator
// shells out to during Apply — config enumeration, `up`, targeted `up`, ordered
// health-gated start, and stop — against a REAL throwaway compose project.
//
// These are the methods exercised by Apply's Phase 4 (compose-up) that pure unit
// tests cannot reach: composeServices/composeImages (config parsers),
// ApplyCompose (full `up -d --remove-orphans`), ApplyComposeServices (targeted
// `up -d --no-deps` with the undefined-service filter), StartServices (ordered
// `up` + WaitHealthy gating), StopServices (already-stopped tolerance), and
// PullImages (defined + local-ref filtering).
//
// SAFETY: every project is written into its own t.TempDir(), so the compose
// project name (derived from the dir basename) is unique — this scopes
// `--remove-orphans` to the throwaway project and can never reconcile-away the
// real vectis-* stack. Service names use uniqueService() (itest-<pid>-<seq>) so
// the derived container_name (vectis-itest-…) cannot collide with a real
// service container, and every service carries the `vectis-itest=1` label so
// TestMain's sweep collects anything a panic leaves behind. Per-test cleanup
// also runs `docker compose down` on the throwaway project.
//
// NOT covered here (deliberately, and not safely automatable on a box running
// the live stack): the orchestrator-level Apply()/Plan() state machine (needs
// Postgres + valkey + snapshots and reads live container versions) and the
// self-replace helper (it recreates the orchestrator container). Those remain
// walkthrough/canary territory. PullImages' real network pull is also skipped —
// only its deterministic, offline filtering logic is asserted.
//
// Shares TestMain/sweep, requireDocker, probeImage/probeLabel, uniqueService,
// eventually, and sliceContains with docker_dockertest_test.go (same package +
// build tag). Run: `go test -tags dockertest ./internal/orchestrator/`.

package orchestrator

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// composeSvc describes one service to render into a throwaway compose project.
type composeSvc struct {
	name      string // compose service key; container_name becomes vectis-<name>
	image     string // image ref; "" → probeImage (alpine:3.24)
	withHealth bool  // emit a fast always-passing healthcheck (for StartServices)
}

// composeManager returns a DockerManager pointed at the given compose file with
// non-zero timeouts. The Config{} used by newTestDockerManager leaves
// HealthCheckTimeout at 0, which would make WaitHealthy time out instantly — so
// the compose-lifecycle tests need their own manager.
func composeManager(file string) *DockerManager {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewDockerManager(Config{
		ComposePaths:       []string{file},
		HealthCheckTimeout: 30 * time.Second,
		ImagePullTimeout:   60 * time.Second,
	}, logger)
}

// writeComposeProject renders a throwaway docker-compose.yml into a fresh
// t.TempDir() (unique project name → isolated --remove-orphans), registers a
// `compose down` cleanup, and returns the file path.
func writeComposeProject(t *testing.T, svcs ...composeSvc) string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "docker-compose.yml")

	var b strings.Builder
	b.WriteString("services:\n")
	for _, s := range svcs {
		img := s.image
		if img == "" {
			img = probeImage
		}
		b.WriteString("  " + s.name + ":\n")
		b.WriteString("    image: " + img + "\n")
		b.WriteString("    container_name: vectis-" + s.name + "\n")
		// Long-lived no-op so the container stays "running" for inspection.
		b.WriteString("    command: [\"sleep\", \"600\"]\n")
		// init: true puts tini at PID 1 so it forwards SIGTERM to `sleep` and
		// reaps it — without this, `sleep` as PID 1 ignores SIGTERM and
		// StopServices' `docker stop --time 30` blocks the full 30s grace before
		// SIGKILL. Real vectis services handle SIGTERM, so this also makes the
		// throwaway containers behave representatively (and keeps the test fast).
		b.WriteString("    init: true\n")
		b.WriteString("    labels:\n")
		b.WriteString("      - \"" + probeLabel + "\"\n")
		if s.withHealth {
			b.WriteString("    healthcheck:\n")
			b.WriteString("      test: [\"CMD-SHELL\", \"true\"]\n")
			b.WriteString("      interval: 1s\n")
			b.WriteString("      timeout: 2s\n")
			b.WriteString("      retries: 1\n")
			b.WriteString("      start_period: 0s\n")
		}
	}

	if err := os.WriteFile(file, []byte(b.String()), 0644); err != nil {
		t.Fatalf("write compose file: %v", err)
	}
	// `down` (same -f, same default project) removes whatever `up` created even
	// if a test fails mid-flight; the label sweep in TestMain is the backstop.
	t.Cleanup(func() {
		_ = exec.Command("docker", "compose", "-f", file, "down", "-v", "--remove-orphans", "-t", "1").Run()
	})
	return file
}

// inspectStatus returns the container State.Status for a service, or "" on error
// (e.g. the container does not exist).
func inspectStatus(t *testing.T, dm *DockerManager, svc string) string {
	t.Helper()
	info, err := dm.InspectContainer(context.Background(), svc)
	if err != nil {
		return ""
	}
	return info.State.Status
}

// ── composeServices + composeImages (config parsers) ─────────────────

// Both parsers read `docker compose config` output without bringing anything
// up, so this case is fast and fully offline.
func TestDockerManager_ComposeServicesAndImages(t *testing.T) {
	requireDocker(t)

	alpineSvc := uniqueService()
	localSvc := uniqueService()
	localRef := "vectis-localref-itest:dev" // never pulled; just parsed
	file := writeComposeProject(t,
		composeSvc{name: alpineSvc},
		composeSvc{name: localSvc, image: localRef},
	)
	dm := composeManager(file)
	ctx := context.Background()

	defined, err := dm.composeServices(ctx)
	if err != nil {
		t.Fatalf("composeServices: %v", err)
	}
	if !defined[alpineSvc] || !defined[localSvc] {
		t.Errorf("composeServices = %v, want both %s and %s", defined, alpineSvc, localSvc)
	}

	images, err := dm.composeImages(ctx)
	if err != nil {
		t.Fatalf("composeImages: %v", err)
	}
	if images[alpineSvc] != probeImage {
		t.Errorf("image[%s] = %q, want %q", alpineSvc, images[alpineSvc], probeImage)
	}
	if images[localSvc] != localRef {
		t.Errorf("image[%s] = %q, want %q", localSvc, images[localSvc], localRef)
	}
}

// ── ApplyCompose (full `up -d --remove-orphans`) ─────────────────────

func TestDockerManager_ApplyCompose(t *testing.T) {
	requireDocker(t)

	a := uniqueService()
	bSvc := uniqueService()
	file := writeComposeProject(t, composeSvc{name: a}, composeSvc{name: bSvc})
	dm := composeManager(file)
	ctx := context.Background()

	if err := dm.ApplyCompose(ctx); err != nil {
		t.Fatalf("ApplyCompose: %v", err)
	}
	for _, svc := range []string{a, bSvc} {
		if st := inspectStatus(t, dm, svc); st != "running" {
			t.Errorf("after ApplyCompose, %s status = %q, want running", svc, st)
		}
	}
}

// ── ApplyComposeServices (targeted up + undefined filter) ────────────

func TestDockerManager_ApplyComposeServices(t *testing.T) {
	requireDocker(t)

	defined := uniqueService()
	undefined := uniqueService() // in the request list, NOT in the compose file
	file := writeComposeProject(t, composeSvc{name: defined})
	dm := composeManager(file)
	ctx := context.Background()

	// A mixed list brings up only the defined service; the undefined one is
	// filtered out rather than aborting the whole command with "no such service".
	if err := dm.ApplyComposeServices(ctx, []string{defined, undefined}); err != nil {
		t.Fatalf("ApplyComposeServices(mixed): %v", err)
	}
	if st := inspectStatus(t, dm, defined); st != "running" {
		t.Errorf("defined service status = %q, want running", st)
	}
	if st := inspectStatus(t, dm, undefined); st != "" {
		t.Errorf("undefined service should not exist, got status %q", st)
	}

	// A list of only-undefined services filters down to nothing → no-op, no error.
	if err := dm.ApplyComposeServices(ctx, []string{undefined}); err != nil {
		t.Errorf("ApplyComposeServices(all-undefined): want nil, got %v", err)
	}

	// An empty list is a programming error, surfaced as such.
	if err := dm.ApplyComposeServices(ctx, nil); err == nil {
		t.Error("ApplyComposeServices(nil): expected error, got nil")
	}
}

// ── StartServices + StopServices (health-gated start, stop tolerance) ─

func TestDockerManager_StartAndStopServices(t *testing.T) {
	requireDocker(t)

	svc := uniqueService()
	undefined := uniqueService() // exercises the start-order skip path
	file := writeComposeProject(t, composeSvc{name: svc, withHealth: true})
	dm := composeManager(file)
	ctx := context.Background()

	// Ordered start brings the defined service up and blocks on its healthcheck;
	// the undefined entry is skipped, not fatal.
	if err := dm.StartServices(ctx, []string{svc, undefined}); err != nil {
		t.Fatalf("StartServices: %v", err)
	}
	if st := inspectStatus(t, dm, svc); st != "running" {
		t.Fatalf("after StartServices, %s status = %q, want running", svc, st)
	}
	// StartServices only returns once the service is healthy, so this is settled.
	if h, _ := dm.containerHealthStatus(ctx, "vectis-"+svc); h != "healthy" {
		t.Errorf("health after StartServices = %q, want healthy", h)
	}

	// Stop transitions the container out of "running".
	if err := dm.StopServices(ctx, []string{svc}); err != nil {
		t.Fatalf("StopServices: %v", err)
	}
	if st := inspectStatus(t, dm, svc); st == "running" {
		t.Errorf("after StopServices, %s still running", svc)
	}

	// Stopping an already-stopped service is tolerated (no "is not running" error).
	if err := dm.StopServices(ctx, []string{svc}); err != nil {
		t.Errorf("StopServices(already stopped): want nil, got %v", err)
	}
}

// ── PullImages (filtering only — offline) ────────────────────────────

// Only the deterministic filtering logic is asserted: a local-ref service is
// skipped (isLocalImageRef), an undefined service is skipped (not in compose),
// so with no pullable service PullImages returns nil WITHOUT touching the
// network. The real `docker compose pull` shell-out is left to canary runs.
func TestDockerManager_PullImages_Filtering(t *testing.T) {
	requireDocker(t)

	localSvc := uniqueService()
	undefined := uniqueService()
	file := writeComposeProject(t, composeSvc{name: localSvc, image: "vectis-localref-itest:dev"})
	dm := composeManager(file)
	ctx := context.Background()

	// localSvc is defined but local-ref (skipped); undefined isn't in the file
	// (skipped). Nothing left to pull → nil, and no container is created.
	if err := dm.PullImages(ctx, []string{localSvc, undefined}); err != nil {
		t.Errorf("PullImages(all-filtered): want nil, got %v", err)
	}
	if st := inspectStatus(t, dm, localSvc); st != "" {
		t.Errorf("PullImages must not create containers; %s status = %q", localSvc, st)
	}
}
