package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// NetworkDrift describes one container that has drifted off one or more
// of its compose-declared Docker networks at watchdog-check time.
type NetworkDrift struct {
	Service    string            // compose service name (e.g. "api")
	Container  string            // Docker container name (e.g. "vectis-api")
	Missing    []string          // project-prefixed network names the container should be on but isn't
	Healed     []string          // subset of Missing that we successfully reconnected
	HealErrors map[string]string // per-network heal failures, keyed by project-prefixed network name
}

// CheckAndHealNetworks compares each Vectis container's current Docker
// network attachments against its compose declaration, reconnects any
// that are missing, and returns one NetworkDrift entry per affected
// container. Containers that are absent (not running) are skipped silently
// — image-pull / start phases surface those separately.
//
// Driven by the prod incident on 2026-04-27 where `docker compose run --rm
// --no-deps api ...` (the documented admin reset-password recovery path,
// pre-fix) silently disconnected vectis-api from vectis_vectis-data and
// never re-attached when the transient container failed to come up.
// vectis-api stayed on its other networks so its healthcheck still passed,
// but every DB-backed request returned 500 for several minutes until the
// drift was caught by hand. See deferred-items.md §11.
func (dm *DockerManager) CheckAndHealNetworks(ctx context.Context) ([]NetworkDrift, error) {
	expected, err := dm.composeServiceNetworks(ctx)
	if err != nil {
		return nil, fmt.Errorf("read compose networks: %w", err)
	}

	services := make([]string, 0, len(expected))
	for s := range expected {
		services = append(services, s)
	}
	sort.Strings(services)

	var drifts []NetworkDrift
	for _, service := range services {
		expectedNets := expected[service]
		if len(expectedNets) == 0 {
			continue
		}

		cname := containerName(service)
		actual, err := dm.containerNetworks(ctx, cname)
		if err != nil {
			dm.logger.Debug("network check skipped: cannot inspect container",
				"container", cname, "error", err)
			continue
		}

		var missing []string
		for _, nw := range expectedNets {
			if !actual[nw] {
				missing = append(missing, nw)
			}
		}
		if len(missing) == 0 {
			continue
		}
		sort.Strings(missing)

		drift := NetworkDrift{
			Service:    service,
			Container:  cname,
			Missing:    missing,
			HealErrors: map[string]string{},
		}
		for _, nw := range missing {
			if err := dm.connectNetwork(ctx, nw, cname); err != nil {
				drift.HealErrors[nw] = err.Error()
				continue
			}
			drift.Healed = append(drift.Healed, nw)
		}
		drifts = append(drifts, drift)
	}
	return drifts, nil
}

// composeServiceNetworks returns the project-prefixed Docker network names
// each compose service should be attached to. Uses the top-level networks
// map's resolved 'name' field instead of guessing project prefixes.
//
// Services whose containers are not under our control (e.g. a 'container_name'
// that isn't 'vectis-<service>') are still included; the caller decides
// whether to act on them. In practice every Vectis service follows the
// 'vectis-<service>' convention, enforced by config_test.
func (dm *DockerManager) composeServiceNetworks(ctx context.Context) (map[string][]string, error) {
	args := append([]string{"compose"}, dm.cfg.composeFileArgs()...)
	args = append(args, "config", "--format", "json")
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker compose config: %w", err)
	}
	return parseComposeServiceNetworks(stdout.Bytes())
}

// parseComposeServiceNetworks parses the JSON emitted by `docker compose
// config --format json` and returns service → list of project-prefixed
// Docker network names. Split out for testability.
func parseComposeServiceNetworks(raw []byte) (map[string][]string, error) {
	var parsed struct {
		Networks map[string]struct {
			Name string `json:"name"`
		} `json:"networks"`
		Services map[string]struct {
			Networks map[string]json.RawMessage `json:"networks"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("parse compose json: %w", err)
	}

	out := make(map[string][]string, len(parsed.Services))
	for svc, def := range parsed.Services {
		if len(def.Networks) == 0 {
			continue
		}
		nets := make([]string, 0, len(def.Networks))
		for logical := range def.Networks {
			top, ok := parsed.Networks[logical]
			if !ok || top.Name == "" {
				return nil, fmt.Errorf("service %q references undeclared network %q", svc, logical)
			}
			nets = append(nets, top.Name)
		}
		sort.Strings(nets)
		out[svc] = nets
	}
	return out, nil
}

// containerNetworks returns the set of Docker networks the named container
// is currently attached to. Keys are project-prefixed names matching the
// values returned by composeServiceNetworks.
func (dm *DockerManager) containerNetworks(ctx context.Context, cname string) (map[string]bool, error) {
	cmd := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{json .NetworkSettings.Networks}}",
		cname,
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker inspect %s: %s — %w",
			cname, strings.TrimSpace(stderr.String()), err)
	}
	var nets map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &nets); err != nil {
		return nil, fmt.Errorf("parse network JSON for %s: %w", cname, err)
	}
	out := make(map[string]bool, len(nets))
	for name := range nets {
		out[name] = true
	}
	return out, nil
}

// connectNetwork attaches a container to a Docker network. Treats Docker's
// "endpoint already exists" race as success — two watchdog ticks landing
// on the same drift mid-heal must not produce phantom errors.
func (dm *DockerManager) connectNetwork(ctx context.Context, network, container string) error {
	cmd := exec.CommandContext(ctx, "docker", "network", "connect", network, container)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	combined := strings.ToLower(string(out))
	if strings.Contains(combined, "already exists") || strings.Contains(combined, "is already attached") {
		return nil
	}
	return fmt.Errorf("docker network connect %s %s: %s — %w",
		network, container, strings.TrimSpace(string(out)), err)
}

// RunNetworkWatchdog is a long-running loop that periodically checks every
// Vectis container for drift off its declared compose networks and self-
// heals where possible. Designed to be called as a goroutine from
// cmd/orchestrator/main.go.
//
// The first pass runs immediately on entry so a freshly-restarted
// orchestrator catches drift accumulated during its downtime instead of
// waiting a full interval.
func RunNetworkWatchdog(ctx context.Context, dm *DockerManager, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	logger = logger.With("component", "network_watchdog")
	logger.Info("starting network drift watchdog", "interval", interval)

	runOnceWithLog(ctx, dm, logger)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info("network drift watchdog stopping")
			return
		case <-ticker.C:
			runOnceWithLog(ctx, dm, logger)
		}
	}
}

func runOnceWithLog(ctx context.Context, dm *DockerManager, logger *slog.Logger) {
	drifts, err := dm.CheckAndHealNetworks(ctx)
	if err != nil {
		logger.Warn("network drift check failed", "error", err)
		return
	}
	for _, d := range drifts {
		if len(d.Healed) > 0 {
			logger.Warn("network drift detected — reconnected",
				"service", d.Service,
				"container", d.Container,
				"healed", d.Healed,
			)
		}
		if len(d.HealErrors) > 0 {
			logger.Error("network drift heal failed",
				"service", d.Service,
				"container", d.Container,
				"errors", d.HealErrors,
			)
		}
	}
}
