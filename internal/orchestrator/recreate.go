package orchestrator

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Recreate applies compose-level changes made by `vectis config apply` (#262):
// container environment, healthchecks, resource limits, mounts, and optional
// services switched on or off. A reload or `docker restart` never picks these
// up; only recreating the container from the (already rewritten) compose does.
//
// It runs under the same advisory lock as plan/apply and in its own state,
// `recreating`, so an update can't start halfway through. It's not part of the
// update pipeline and has no rollback: the change is configuration, not a
// version, and `config apply` keeps a compose backup for a manual restore.

// RecreateRequest names the services whose compose block changed (Services,
// including newly added ones) and those removed from the compose (Removed).
type RecreateRequest struct {
	Services []string `json:"services"`
	Removed  []string `json:"removed"`
}

// RecreateStep is the outcome for one service.
type RecreateStep struct {
	Service string `json:"service"`
	Action  string `json:"action"` // "recreate" | "remove"
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Seconds int    `json:"seconds"`
}

// RecreateResult is returned to `vectis config apply`.
type RecreateResult struct {
	Success bool           `json:"success"`
	Steps   []RecreateStep `json:"steps"`
	// Skipped lists requested work that was not attempted because an earlier
	// step failed.
	Skipped []string `json:"skipped,omitempty"`
}

var recreateServiceNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

// recreateNotRemovable are services the stack can't run without. The compose
// template always renders them, so a request to remove one is a bug or a
// tampered request, never a config change.
var recreateNotRemovable = map[string]bool{
	"postgres": true, "valkey": true, "api": true, "orchestrator": true,
	"postfix": true, "dovecot": true, "rspamd": true, "traefik": true, "cert-extractor": true,
}

// RecreateMaxDuration bounds one recreate run (the slowest service, ClamAV,
// alone may take 3 minutes to report healthy).
const RecreateMaxDuration = 15 * time.Minute

// recreateDefaultTimeout applies to services without an entry in
// ServiceHealthTimeouts (traefik, webmail, cert-extractor, observability).
const recreateDefaultTimeout = 60 * time.Second

// validateRecreateRequest checks a request against the services defined in the
// live compose. The orchestrator never recreates itself here: that goes
// through `vectis update apply`'s self-replace helper.
func validateRecreateRequest(req RecreateRequest, defined map[string]bool) error {
	if len(req.Services) == 0 && len(req.Removed) == 0 {
		return fmt.Errorf("nothing to recreate")
	}
	seen := map[string]bool{}
	for _, list := range [][]string{req.Services, req.Removed} {
		for _, s := range list {
			if !recreateServiceNameRe.MatchString(s) {
				return fmt.Errorf("invalid service name %q", s)
			}
			if s == "orchestrator" {
				return fmt.Errorf("the orchestrator can't recreate itself; run `vectis update apply`")
			}
			if seen[s] {
				return fmt.Errorf("service %q listed twice", s)
			}
			seen[s] = true
		}
	}
	for _, s := range req.Services {
		if !defined[s] {
			return fmt.Errorf("service %q is not defined in the compose file", s)
		}
	}
	for _, s := range req.Removed {
		if recreateNotRemovable[s] {
			return fmt.Errorf("service %q can't be removed", s)
		}
		if defined[s] {
			return fmt.Errorf("service %q is still defined in the compose file", s)
		}
	}
	return nil
}

// recreateOrder puts services in dependency order: ServiceStartOrder first
// (postgres, valkey, mail services, api), then the rest alphabetically.
func recreateOrder(services []string) []string {
	rank := map[string]int{}
	for i, s := range ServiceStartOrder {
		rank[s] = i
	}
	out := append([]string(nil), services...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, iok := rank[out[i]]
		rj, jok := rank[out[j]]
		switch {
		case iok && jok:
			return ri < rj
		case iok != jok:
			return iok
		default:
			return out[i] < out[j]
		}
	})
	return out
}

// Recreate removes the services dropped from the compose, then recreates the
// changed ones in dependency order, each health-gated. It stops at the first
// failure and reports the rest as skipped.
func (o *Orchestrator) Recreate(ctx context.Context, req RecreateRequest) (*RecreateResult, error) {
	// Fail fast instead of queueing behind a running apply on the lock.
	if !o.sm.State().CanRecreate() {
		return nil, &ErrInvalidTransition{From: o.sm.State(), Op: "recreate"}
	}
	release, err := o.acquireAdvisoryLock(ctx)
	if err != nil {
		return nil, fmt.Errorf("orchestrator busy: %w", err)
	}
	defer release()
	if !o.sm.State().CanRecreate() {
		return nil, &ErrInvalidTransition{From: o.sm.State(), Op: "recreate"}
	}

	defined, err := o.docker.composeServices(ctx)
	if err != nil {
		return nil, fmt.Errorf("enumerate compose services: %w", err)
	}
	if err := validateRecreateRequest(req, defined); err != nil {
		return nil, &ErrRecreateRequest{Reason: err.Error()}
	}

	if err := o.sm.Transition(ctx, StateRecreating); err != nil {
		return nil, err
	}
	opID, err := o.sm.RecordOperation(ctx, "recreate", "running", "",
		map[string]any{"services": req.Services, "removed": req.Removed}, nil)
	if err != nil {
		o.logger.Warn("recreate: could not record operation", "error", err)
	}

	type job struct{ svc, action string }
	var jobs []job
	for _, s := range req.Removed {
		jobs = append(jobs, job{s, "remove"})
	}
	for _, s := range recreateOrder(req.Services) {
		jobs = append(jobs, job{s, "recreate"})
	}

	res := &RecreateResult{Success: true}
	for i, j := range jobs {
		start := time.Now()
		var stepErr error
		if j.action == "remove" {
			stepErr = o.docker.RemoveServiceContainer(ctx, j.svc)
		} else {
			stepErr = o.docker.ApplyComposeServices(ctx, []string{j.svc})
			if stepErr == nil {
				timeout, ok := ServiceHealthTimeouts[j.svc]
				if !ok {
					timeout = recreateDefaultTimeout
				}
				stepErr = o.docker.WaitHealthyOrRunning(ctx, j.svc, timeout)
			}
		}
		step := RecreateStep{Service: j.svc, Action: j.action, Success: stepErr == nil, Seconds: int(time.Since(start).Seconds())}
		if stepErr != nil {
			step.Error = stepErr.Error()
			res.Success = false
			res.Steps = append(res.Steps, step)
			for _, rest := range jobs[i+1:] {
				res.Skipped = append(res.Skipped, rest.svc)
			}
			o.logger.Error("recreate step failed", "service", j.svc, "action", j.action, "error", stepErr)
			break
		}
		res.Steps = append(res.Steps, step)
		o.logger.Info("recreate step done", "service", j.svc, "action", j.action, "seconds", step.Seconds)
	}

	status, final, msg := "completed", StateIdle, ""
	if !res.Success {
		status, final = "failed", StateFailed
		last := res.Steps[len(res.Steps)-1]
		msg = fmt.Sprintf("%s %s: %s", last.Action, last.Service, last.Error)
	}
	if opID != "" {
		// A recreated postgres drops the pool's connections; retry briefly.
		for attempt := 0; attempt < 10; attempt++ {
			if err := o.sm.CompleteOperation(ctx, opID, status, "", msg); err == nil {
				break
			} else if attempt == 9 {
				o.logger.Warn("recreate: could not complete operation record", "error", err)
			}
			time.Sleep(3 * time.Second)
		}
	}
	if err := o.sm.Transition(ctx, final); err != nil {
		o.logger.Error("recreate: final state transition failed", "to", final, "error", err)
	}
	return res, nil
}

// ErrRecreateRequest is a request the orchestrator refuses (400, not 500).
type ErrRecreateRequest struct{ Reason string }

func (e *ErrRecreateRequest) Error() string { return "invalid recreate request: " + e.Reason }

// RemoveServiceContainer stops and removes a service's container after the
// service was dropped from the compose (e.g. ClamAV or webmail switched off).
// A container that's already gone counts as removed.
func (dm *DockerManager) RemoveServiceContainer(ctx context.Context, service string) error {
	name := containerName(service)
	// Graceful stop first (30 s), then remove; named volumes are kept.
	for _, args := range [][]string{{"stop", "-t", "30", name}, {"rm", name}} {
		out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil && !strings.Contains(strings.ToLower(string(out)), "no such container") {
			return fmt.Errorf("docker %s %s: %w: %s", args[0], name, err, strings.TrimSpace(string(out)))
		}
	}
	dm.logger.Info("removed service container", "service", service, "container", name)
	return nil
}

// WaitHealthyOrRunning waits for a recreated container: until its healthcheck
// reports healthy, or, for a container without a healthcheck, until it has
// been running for a few seconds. WaitHealthy alone would wait out the whole
// timeout on the latter.
func (dm *DockerManager) WaitHealthyOrRunning(ctx context.Context, service string, timeout time.Duration) error {
	name := containerName(service)
	deadline := time.Now().Add(timeout)
	var runningSince time.Time
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		out, err := exec.CommandContext(ctx, "docker", "inspect", "--format",
			"{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", name).Output()
		if err == nil {
			f := strings.Fields(string(out))
			if len(f) == 2 {
				switch {
				case f[1] == "healthy":
					return nil
				case f[1] == "unhealthy":
					return fmt.Errorf("container %s is unhealthy", name)
				case f[1] == "none" && f[0] == "running":
					if runningSince.IsZero() {
						runningSince = time.Now()
					} else if time.Since(runningSince) >= 5*time.Second {
						return nil
					}
				case f[0] == "exited" || f[0] == "dead":
					return fmt.Errorf("container %s %s", name, f[0])
				default:
					runningSince = time.Time{}
				}
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("container %s not healthy after %s", name, timeout)
}
