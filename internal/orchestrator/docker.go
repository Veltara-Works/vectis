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
// Each pull is bounded by Config.ImagePullTimeout.
func (dm *DockerManager) PullImages(ctx context.Context, services []string) error {
	dm.logger.Info("pulling images", "services", services)

	var (
		mu   sync.Mutex
		errs []string
		wg   sync.WaitGroup
	)

	for _, svc := range services {
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

// pullImage pulls the image for a single service using docker compose pull.
func (dm *DockerManager) pullImage(ctx context.Context, service string) error {
	dm.logger.Info("pulling image", "service", service)

	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", dm.cfg.ComposePath,
		"pull", service,
	)

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

		cmd := exec.CommandContext(ctx, "docker", "compose",
			"-f", dm.cfg.ComposePath,
			"up", "-d", "--no-deps", svc,
		)

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
func (dm *DockerManager) GetContainerVersions(ctx context.Context) (map[string]string, error) {
	versions := make(map[string]string)

	for _, svc := range ServiceStartOrder {
		name := containerName(svc)
		image, err := dm.getContainerImage(ctx, name)
		if err != nil {
			dm.logger.Debug("could not get image for container",
				"service", svc,
				"container", name,
				"error", err,
			)
			continue // Container may not exist yet.
		}
		versions[svc] = image
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

// ApplyCompose runs docker compose up -d with the given compose file path.
// This applies any changes to service definitions (new images, config, etc.).
func (dm *DockerManager) ApplyCompose(ctx context.Context, composePath string) error {
	dm.logger.Info("applying docker compose", "path", composePath)

	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", composePath,
		"up", "-d",
		"--remove-orphans",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker compose up: %w: %s", err, string(output))
	}

	dm.logger.Info("docker compose applied", "path", composePath)
	return nil
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
