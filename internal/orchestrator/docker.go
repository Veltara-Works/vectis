package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// DockerManager handles container lifecycle operations via the docker CLI.
// All Vectis containers are prefixed with "vectis-".
type DockerManager struct {
	cfg    Config
	logger *slog.Logger
}

// NewDockerManager creates a DockerManager.
func NewDockerManager(cfg Config, logger *slog.Logger) *DockerManager {
	return &DockerManager{
		cfg:    cfg,
		logger: logger,
	}
}

// containerName returns the Docker container name for a Vectis service.
func containerName(service string) string {
	return "vectis-" + service
}

// PullImages pulls container images in parallel for the given services.
// Services not defined in the compose file are skipped. Services whose image
// reference is a locally-built tag (no registry hostname, e.g. "vectis-api:dev")
// are also skipped — pulling them would fail with "denied" against ghcr.io.
// Each remaining pull is bounded by Config.ImagePullTimeout.
func (dm *DockerManager) PullImages(ctx context.Context, services []string) error {
	defined, err := dm.composeServices(ctx)
	if err != nil {
		return fmt.Errorf("enumerate compose services: %w", err)
	}

	images, err := dm.composeImages(ctx)
	if err != nil {
		return fmt.Errorf("enumerate compose images: %w", err)
	}

	var toPull []string
	for _, svc := range services {
		if !defined[svc] {
			dm.logger.Info("skipping pull: service not defined in compose", "service", svc)
			continue
		}
		img := images[svc]
		if isLocalImageRef(img) {
			dm.logger.Info("skipping pull: local image reference", "service", svc, "image", img)
			continue
		}
		toPull = append(toPull, svc)
	}

	if len(toPull) == 0 {
		dm.logger.Info("pulling images: nothing to pull after filtering")
		return nil
	}

	dm.logger.Info("pulling images", "services", toPull)

	var (
		mu   sync.Mutex
		errs []string
		wg   sync.WaitGroup
	)

	for _, svc := range toPull {
		wg.Add(1)
		go func(service string) {
			defer wg.Done()

			pullCtx, cancel := context.WithTimeout(ctx, dm.cfg.ImagePullTimeout)
			defer cancel()

			if err := dm.pullImage(pullCtx, service); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Sprintf("%s: %v", service, err))
				mu.Unlock()
			}
		}(svc)
	}

	wg.Wait()

	if len(errs) > 0 {
		return fmt.Errorf("image pull failures: %s", strings.Join(errs, "; "))
	}
	return nil
}

// isLocalImageRef reports whether an image reference points to a locally-built
// image rather than a remote registry. Any reference without a dotted hostname
// before the first slash (or with no slash at all) is treated as local: Docker
// would default such refs to Docker Hub, which for our services means "this is
// our locally-built :dev tag". Empty strings are treated as local (skip pull).
func isLocalImageRef(ref string) bool {
	if ref == "" {
		return true
	}
	slash := strings.Index(ref, "/")
	if slash < 0 {
		// No slash at all → "name:tag" form → locally built or Docker Hub library.
		return true
	}
	host := ref[:slash]
	// Registry hostnames always contain a "." (ghcr.io, docker.io, quay.io) or
	// a ":" for a port, or are literally "localhost".
	if strings.ContainsAny(host, ".:") || host == "localhost" {
		return false
	}
	// e.g. "library/postgres" — treat as Docker Hub official, pull.
	return false
}

// composeServices returns the set of service names defined in the compose file.
func (dm *DockerManager) composeServices(ctx context.Context) (map[string]bool, error) {
	args := append([]string{"compose"}, dm.cfg.composeFileArgs()...)
	args = append(args, "config", "--services")
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker compose config --services: %w", err)
	}

	out := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out[line] = true
		}
	}
	return out, nil
}

// composeImages returns the image reference per service as defined in the
// compose file. Maps service name → image (e.g. "vectis-api:dev").
func (dm *DockerManager) composeImages(ctx context.Context) (map[string]string, error) {
	args := append([]string{"compose"}, dm.cfg.composeFileArgs()...)
	args = append(args, "config", "--format", "json")
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker compose config --format json: %w", err)
	}

	var parsed struct {
		Services map[string]struct {
			Image string `json:"image"`
		} `json:"services"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		return nil, fmt.Errorf("parse compose json: %w", err)
	}

	out := make(map[string]string, len(parsed.Services))
	for name, svc := range parsed.Services {
		out[name] = svc.Image
	}
	return out, nil
}

// pullImage pulls the image for a single service using docker compose pull.
func (dm *DockerManager) pullImage(ctx context.Context, service string) error {
	dm.logger.Info("pulling image", "service", service)

	args := append([]string{"compose"}, dm.cfg.composeFileArgs()...)
	args = append(args, "pull", service)
	cmd := exec.CommandContext(ctx, "docker", args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker compose pull %s: %w: %s", service, err, string(output))
	}

	dm.logger.Info("image pulled", "service", service)
	return nil
}

// StopServices stops containers in the given order (should be reverse dependency order).
// Each container is stopped gracefully with a 30-second timeout.
func (dm *DockerManager) StopServices(ctx context.Context, order []string) error {
	dm.logger.Info("stopping services", "order", order)

	for _, svc := range order {
		name := containerName(svc)
		dm.logger.Info("stopping container", "service", svc, "container", name)

		cmd := exec.CommandContext(ctx, "docker", "stop", "--time", "30", name)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// If the container is already stopped or doesn't exist, that's fine.
			outStr := string(output)
			if strings.Contains(outStr, "No such container") ||
				strings.Contains(outStr, "is not running") {
				dm.logger.Info("container already stopped", "service", svc)
				continue
			}
			return fmt.Errorf("stop %s: %w: %s", svc, err, outStr)
		}
	}

	dm.logger.Info("all services stopped")
	return nil
}

// StartServices starts containers in the given order (should be dependency order).
// Uses docker compose up with the specific service names.
func (dm *DockerManager) StartServices(ctx context.Context, order []string) error {
	dm.logger.Info("starting services", "order", order)

	for _, svc := range order {
		dm.logger.Info("starting service", "service", svc)

		args := append([]string{"compose"}, dm.cfg.composeFileArgs()...)
		args = append(args, "up", "-d", "--no-deps", svc)
		cmd := exec.CommandContext(ctx, "docker", args...)

		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("start %s: %w: %s", svc, err, string(output))
		}

		// Wait for health check before starting the next dependent service.
		timeout, ok := ServiceHealthTimeouts[svc]
		if !ok {
			timeout = dm.cfg.HealthCheckTimeout
		}

		if err := dm.WaitHealthy(ctx, svc, timeout); err != nil {
			return fmt.Errorf("health check failed for %s: %w", svc, err)
		}

		dm.logger.Info("service started and healthy", "service", svc)
	}

	dm.logger.Info("all services started")
	return nil
}

// WaitHealthy polls Docker until the container's HEALTHCHECK reports healthy
// or the timeout expires. Returns an error if the container does not become
// healthy within the timeout.
func (dm *DockerManager) WaitHealthy(ctx context.Context, service string, timeout time.Duration) error {
	name := containerName(service)
	deadline := time.Now().Add(timeout)
	pollInterval := 2 * time.Second

	dm.logger.Info("waiting for health check",
		"service", service,
		"container", name,
		"timeout", timeout.String(),
	)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		status, err := dm.containerHealthStatus(ctx, name)
		if err != nil {
			dm.logger.Debug("health check probe error", "service", service, "error", err)
			time.Sleep(pollInterval)
			continue
		}

		switch status {
		case "healthy":
			return nil
		case "unhealthy":
			return fmt.Errorf("container %s is unhealthy", name)
		default:
			// "starting" or no health check defined — keep polling.
			time.Sleep(pollInterval)
		}
	}

	return fmt.Errorf("health check timeout for %s after %s", service, timeout)
}

// containerHealthStatus returns the health status of a container via docker inspect.
// Returns "healthy", "unhealthy", "starting", or "none" (no health check).
func (dm *DockerManager) containerHealthStatus(ctx context.Context, containerName string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
		containerName,
	)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker inspect %s: %w", containerName, err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// GetContainerVersions returns the current image tags for all Vectis containers.
// Keys are service names, values are full image references (e.g. "vectis/api:1.2.3").
//
// Iterates VectisImageServices (everything whose tag moves with releases) plus
// the data services from ServiceStartOrder so Plan's baseline has running
// versions for every upgradable service. Iterating only ServiceStartOrder
// dropped orchestrator + cert-extractor, which made Plan report them as
// "create" instead of "update" — see VectisImageServices doc.
func (dm *DockerManager) GetContainerVersions(ctx context.Context) (map[string]string, error) {
	versions := make(map[string]string)

	seen := make(map[string]bool)
	inspect := func(svc string) {
		if seen[svc] {
			return
		}
		seen[svc] = true
		name := containerName(svc)
		image, err := dm.getContainerImage(ctx, name)
		if err != nil {
			dm.logger.Debug("could not get image for container",
				"service", svc,
				"container", name,
				"error", err,
			)
			return // Container may not exist yet.
		}
		versions[svc] = image
	}
	for _, svc := range VectisImageServices {
		inspect(svc)
	}
	for _, svc := range ServiceStartOrder {
		inspect(svc)
	}

	return versions, nil
}

// getContainerImage returns the image reference for a running container.
func (dm *DockerManager) getContainerImage(ctx context.Context, name string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{.Config.Image}}",
		name,
	)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker inspect %s: %w", name, err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// ApplyCompose runs docker compose up -d across all configured compose files.
// This applies any changes to service definitions (new images, config, etc.).
func (dm *DockerManager) ApplyCompose(ctx context.Context) error {
	dm.logger.Info("applying docker compose", "paths", dm.cfg.ComposePaths)

	args := append([]string{"compose"}, dm.cfg.composeFileArgs()...)
	args = append(args, "up", "-d", "--remove-orphans")
	cmd := exec.CommandContext(ctx, "docker", args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker compose up: %w: %s", err, string(output))
	}

	dm.logger.Info("docker compose applied", "paths", dm.cfg.ComposePaths)
	return nil
}

// ApplyComposeServices runs `docker compose up -d <s1> <s2> …` for exactly the
// listed services, rather than the whole compose like ApplyCompose.
//
// Used by Apply's Phase 4.3 to recreate every vectis-* service EXCEPT the
// orchestrator itself — the orchestrator's self-replacement is handled
// asynchronously via a detached helper (SpawnSelfReplaceHelper). Without the
// split, `docker compose up -d` issued from inside the orchestrator container
// got SIGTERM'd mid-command when the daemon started swapping the orchestrator
// — 0.35s was all Phase 4.3 got before dying (rc33→rc35 walkthrough 2026-04-24).
//
// --remove-orphans is intentionally NOT passed here — we're targeting specific
// services, not reconciling the whole stack, and passing it would remove
// containers we're deliberately leaving alone (orchestrator).
func (dm *DockerManager) ApplyComposeServices(ctx context.Context, services []string) error {
	if len(services) == 0 {
		return fmt.Errorf("ApplyComposeServices called with empty service list")
	}
	dm.logger.Info("applying docker compose for specific services",
		"paths", dm.cfg.ComposePaths, "services", services)

	args := append([]string{"compose"}, dm.cfg.composeFileArgs()...)
	args = append(args, "up", "-d")
	args = append(args, services...)
	cmd := exec.CommandContext(ctx, "docker", args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker compose up %v: %w: %s", services, err, string(output))
	}

	dm.logger.Info("docker compose applied for services", "services", services)
	return nil
}

// SpawnSelfReplaceHelper launches a short-lived detached container that, after
// `delay` seconds, runs `docker compose up -d orchestrator` — triggering a
// recreation of the orchestrator container with whatever image tag is in the
// compose file (rewritten by Phase 3.5 to the target rc). The helper reuses
// the currently-running orchestrator image (guaranteed-working docker CLI
// that can talk to the mounted socket), runs with --rm so it self-cleans,
// and has no network dependencies — just /var/run/docker.sock and /etc/vectis
// bind-mounted in.
//
// Rationale: Phase 4.3's ordinary `docker compose up -d` gets SIGTERM'd
// mid-command when the daemon starts swapping the orchestrator itself — see
// the Apply's Phase 4.3 split comment above. Handing the orchestrator's own
// recreation off to a helper breaks that race: the orchestrator records Apply
// completion cleanly, the helper fires N seconds later, docker sends SIGTERM
// to the orchestrator (which uses its normal graceful-shutdown path), new
// orchestrator starts on the new image. User-visible flow is continuous.
//
// helperImage should be the CURRENT (pre-upgrade) orchestrator image — we
// don't want to depend on the new image being healthy just to launch the
// helper. Returns the helper container ID on success.
func (dm *DockerManager) SpawnSelfReplaceHelper(ctx context.Context, helperImage string, delay time.Duration, helperNameSuffix string) (string, error) {
	if helperImage == "" {
		return "", fmt.Errorf("SpawnSelfReplaceHelper called with empty helperImage")
	}
	if delay < 0 {
		return "", fmt.Errorf("SpawnSelfReplaceHelper called with negative delay %s", delay)
	}
	if helperNameSuffix == "" {
		return "", fmt.Errorf("SpawnSelfReplaceHelper called with empty helperNameSuffix")
	}

	// Compose file inside the helper container is the first of the configured
	// compose paths — the same one Phase 3.5 just rewrote. Helper runs outside
	// the vectis compose project, so we pass -f explicitly.
	composePath := "/etc/vectis/docker-compose.yml"
	if len(dm.cfg.ComposePaths) > 0 {
		composePath = dm.cfg.ComposePaths[0]
	}

	delaySeconds := int(delay.Seconds())
	shCommand := fmt.Sprintf(
		"sleep %d && docker compose -f %s up -d orchestrator",
		delaySeconds, composePath,
	)
	helperName := "vectis-apply-helper-" + helperNameSuffix

	args := []string{
		"run", "-d", "--rm",
		"--name", helperName,
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		"-v", "/etc/vectis:/etc/vectis:ro",
		"--entrypoint", "sh",
		helperImage,
		"-c", shCommand,
	}

	dm.logger.Info("spawning orchestrator self-replace helper",
		"helper_name", helperName,
		"helper_image", helperImage,
		"delay_seconds", delaySeconds,
		"compose_path", composePath,
	)

	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker run helper: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	containerID := strings.TrimSpace(stdout.String())
	dm.logger.Info("self-replace helper spawned",
		"helper_name", helperName,
		"container_id", containerID,
	)
	return containerID, nil
}

// containerInfo holds the inspect output fields we care about.
type containerInfo struct {
	State struct {
		Status string `json:"Status"`
		Health *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image string `json:"Image"`
	} `json:"Config"`
}

// InspectContainer returns parsed container info for a Vectis service.
func (dm *DockerManager) InspectContainer(ctx context.Context, service string) (*containerInfo, error) {
	name := containerName(service)

	cmd := exec.CommandContext(ctx, "docker", "inspect", name)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker inspect %s: %w", name, err)
	}

	var infos []containerInfo
	if err := json.Unmarshal(stdout.Bytes(), &infos); err != nil {
		return nil, fmt.Errorf("unmarshal inspect output for %s: %w", name, err)
	}
	if len(infos) == 0 {
		return nil, fmt.Errorf("no inspect data for container %s", name)
	}

	return &infos[0], nil
}
