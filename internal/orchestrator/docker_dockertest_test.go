//go:build dockertest

// Docker-integration tests for DockerManager. These drive the REAL docker CLI
// (the same way the orchestrator does in production) against throwaway
// containers and networks, exercising the inspect/health/network output parsers
// that pure unit tests cannot reach and that have historically drifted across
// docker versions (phantom containers, lying healthchecks, network endpoints).
//
// SAFETY: every resource these tests create is uniquely named (vectis-itest-*)
// and carries the label `vectis-itest=1`. They run on boxes where the real
// vectis-* stack is live, so they MUST never reference a real service name. The
// subset assertions (contains, not equals) tolerate the real stack's networks
// and containers being present alongside the throwaway ones.
//
// Gated behind the `dockertest` build tag so they are excluded from the default
// `go test` / `go vet` and from the main integration job (which has no docker
// contract). They run in the dedicated "Orchestrator Docker" CI job and on the
// build box (`go test -tags dockertest ./internal/orchestrator/`).

package orchestrator

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	probeImage = "alpine:latest"
	probeLabel = "vectis-itest=1"
)

var probeSeq int64

// TestMain best-effort sweeps any throwaway resources left by a previously
// aborted run (a panic skips t.Cleanup) so the persistent build box does not
// accumulate them. The label filter guarantees the real stack is never touched.
func TestMain(m *testing.M) {
	sweep()
	code := m.Run()
	sweep()
	os.Exit(code)
}

func sweep() {
	if out, err := exec.Command("docker", "ps", "-aq", "--filter", "label="+probeLabel).Output(); err == nil {
		for _, id := range strings.Fields(string(out)) {
			_ = exec.Command("docker", "rm", "-f", id).Run()
		}
	}
	if out, err := exec.Command("docker", "network", "ls", "-q", "--filter", "label="+probeLabel).Output(); err == nil {
		for _, id := range strings.Fields(string(out)) {
			_ = exec.Command("docker", "network", "rm", id).Run()
		}
	}
}

func newTestDockerManager() *DockerManager {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewDockerManager(Config{}, logger)
}

// requireDocker skips the test if the docker daemon is unreachable.
func requireDocker(t *testing.T) {
	t.Helper()
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker daemon not available: %v", err)
	}
}

// uniqueService returns a service name unique to this process+invocation, so the
// derived container name (vectis-<service>) cannot collide with a real vectis-*
// service container on the host.
func uniqueService() string {
	return "itest-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(atomic.AddInt64(&probeSeq, 1), 10)
}

// startProbe runs a detached throwaway container named vectis-<service> from the
// probe image, registers cleanup, and returns nothing (callers derive the name
// from service). Extra args are inserted before the image, e.g. healthcheck or
// --network flags.
func startProbe(t *testing.T, service string, runArgs ...string) {
	t.Helper()
	name := "vectis-" + service
	args := append([]string{"run", "-d", "--name", name, "--label", probeLabel}, runArgs...)
	args = append(args, probeImage, "sleep", "600")
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("start probe %s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
}

func eventually(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return cond()
}

func sliceContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// healthArgs returns docker-run flags for a fast healthcheck running `cmd`
// (`true` → healthy, `false` → unhealthy) with no start grace period.
func healthArgs(cmd string) []string {
	return []string{
		"--health-cmd", cmd,
		"--health-interval", "1s",
		"--health-timeout", "2s",
		"--health-retries", "1",
		"--health-start-period", "0s",
	}
}

// ── InspectContainer ─────────────────────────────────────────────────

func TestDockerManager_InspectContainer(t *testing.T) {
	requireDocker(t)
	dm := newTestDockerManager()
	ctx := context.Background()

	svc := uniqueService()
	startProbe(t, svc)

	info, err := dm.InspectContainer(ctx, svc)
	if err != nil {
		t.Fatalf("InspectContainer: %v", err)
	}
	if info.State.Status != "running" {
		t.Errorf("State.Status = %q, want running", info.State.Status)
	}
	if !strings.HasPrefix(info.Config.Image, "alpine") {
		t.Errorf("Config.Image = %q, want alpine*", info.Config.Image)
	}

	// A non-existent container is an error, not a nil/empty struct.
	if _, err := dm.InspectContainer(ctx, uniqueService()); err == nil {
		t.Error("InspectContainer on missing container: expected error")
	}
}

// ── containerHealthStatus ────────────────────────────────────────────

func TestDockerManager_ContainerHealthStatus(t *testing.T) {
	requireDocker(t)
	dm := newTestDockerManager()
	ctx := context.Background()

	// No healthcheck defined → "none".
	noHC := uniqueService()
	startProbe(t, noHC)
	if s, err := dm.containerHealthStatus(ctx, "vectis-"+noHC); err != nil || s != "none" {
		t.Errorf("health(no healthcheck) = %q, err=%v; want none", s, err)
	}

	// Passing healthcheck → eventually "healthy".
	hc := uniqueService()
	startProbe(t, hc, healthArgs("true")...)
	if !eventually(30*time.Second, func() bool {
		s, _ := dm.containerHealthStatus(ctx, "vectis-"+hc)
		return s == "healthy"
	}) {
		s, _ := dm.containerHealthStatus(ctx, "vectis-"+hc)
		t.Errorf("container never reported healthy (last=%q)", s)
	}
}

// ── WaitHealthy ──────────────────────────────────────────────────────

func TestDockerManager_WaitHealthy(t *testing.T) {
	requireDocker(t)
	dm := newTestDockerManager()
	ctx := context.Background()

	// A container with a passing healthcheck resolves to nil within the timeout.
	good := uniqueService()
	startProbe(t, good, healthArgs("true")...)
	if err := dm.WaitHealthy(ctx, good, 30*time.Second); err != nil {
		t.Errorf("WaitHealthy(healthy): %v", err)
	}

	// A container with a failing healthcheck returns an error promptly.
	bad := uniqueService()
	startProbe(t, bad, healthArgs("false")...)
	if err := dm.WaitHealthy(ctx, bad, 20*time.Second); err == nil {
		t.Error("WaitHealthy(unhealthy): expected error, got nil")
	}
}

// ── getContainerImage ────────────────────────────────────────────────

func TestDockerManager_GetContainerImage(t *testing.T) {
	requireDocker(t)
	dm := newTestDockerManager()

	svc := uniqueService()
	startProbe(t, svc)
	img, err := dm.getContainerImage(context.Background(), "vectis-"+svc)
	if err != nil {
		t.Fatalf("getContainerImage: %v", err)
	}
	if !strings.HasPrefix(img, "alpine") {
		t.Errorf("image = %q, want alpine*", img)
	}
}

// ── listVectisNetworks + containersOnNetwork ─────────────────────────

func TestDockerManager_NetworkEnumeration(t *testing.T) {
	requireDocker(t)
	dm := newTestDockerManager()
	ctx := context.Background()

	netName := "vectis_itest_" + strconv.Itoa(os.Getpid()) + "_" + strconv.FormatInt(atomic.AddInt64(&probeSeq, 1), 10)
	if out, err := exec.Command("docker", "network", "create", "--label", probeLabel, netName).CombinedOutput(); err != nil {
		t.Fatalf("create network %s: %v: %s", netName, err, strings.TrimSpace(string(out)))
	}
	// Registered before the probe so LIFO cleanup removes the container first.
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", netName).Run() })

	svc := uniqueService()
	startProbe(t, svc, "--network", netName)

	// listVectisNetworks matches the vectis_ prefix — our network is in the set
	// (alongside any real stack networks; subset assertion).
	nets, err := dm.listVectisNetworks(ctx)
	if err != nil {
		t.Fatalf("listVectisNetworks: %v", err)
	}
	if !sliceContains(nets, netName) {
		t.Errorf("listVectisNetworks %v missing %s", nets, netName)
	}

	// containersOnNetwork parses `docker network inspect` and returns the probe.
	names, err := dm.containersOnNetwork(ctx, netName)
	if err != nil {
		t.Fatalf("containersOnNetwork: %v", err)
	}
	if !sliceContains(names, "vectis-"+svc) {
		t.Errorf("containersOnNetwork %v missing vectis-%s", names, svc)
	}
}
