package engine

import (
	"fmt"
	"os/exec"
	"strings"
)

// ServiceAction describes what a service needs after config changes.
type ServiceAction struct {
	Service string `json:"service"`
	Action  string `json:"action"` // "none", "reload", "restart"
	Reason  string `json:"reason,omitempty"`
}

// reloadMatrix maps file path prefixes to the services that need action.
// Based on Architecture v1.4 §6 Reload/Restart Matrix.
var reloadMatrix = map[string]struct {
	service string
	action  string
}{
	"postfix/main.cf":                  {service: "postfix", action: "reload"},
	"postfix/master.cf":                {service: "postfix", action: "restart"},
	"postfix/pgsql_virtual_domains.cf": {service: "postfix", action: "none"},
	"postfix/pgsql_virtual_mailboxes.cf": {service: "postfix", action: "none"},
	"postfix/pgsql_virtual_aliases.cf":   {service: "postfix", action: "none"},
	"postfix/pgsql_virtual_catchall.cf":  {service: "postfix", action: "none"},
	"postfix/pgsql_virtual_bcc.cf":       {service: "postfix", action: "none"},
	// transport is texthash — read in memory at startup, needs reload.
	"postfix/transport":                  {service: "postfix", action: "reload"},
	// inbound-notify.sh is copied to /usr/local/bin by the entrypoint on container
	// start (the bind mount is read-only), so changes need a full restart.
	"postfix/inbound-notify.sh":          {service: "postfix", action: "restart"},

	"dovecot/dovecot.conf":           {service: "dovecot", action: "restart"},
	"dovecot/dovecot-sql.conf.ext":   {service: "dovecot", action: "reload"},

	"rspamd/actions.conf":            {service: "rspamd", action: "reload"},
	"rspamd/dkim_signing.conf":       {service: "rspamd", action: "reload"},
	"rspamd/classifier-bayes.conf":   {service: "rspamd", action: "reload"},
	"rspamd/worker-proxy.inc":        {service: "rspamd", action: "restart"},

	"traefik/traefik.yml":            {service: "traefik", action: "restart"},
	"traefik/dynamic.yml":            {service: "traefik", action: "none"}, // Traefik watches file changes
}

// DetermineActions figures out what services need reload/restart based on changed files.
// Higher-priority actions override lower (restart > reload > none).
func DetermineActions(diffs []FileDiff) []ServiceAction {
	// Track the highest-priority action per service.
	serviceActions := make(map[string]string)
	serviceReasons := make(map[string][]string)

	for _, d := range diffs {
		entry, ok := reloadMatrix[d.RelPath]
		if !ok {
			// Files not in the matrix (e.g., docker-compose.yml, acme scripts)
			// don't trigger service actions.
			continue
		}

		current := serviceActions[entry.service]
		if actionPriority(entry.action) > actionPriority(current) {
			serviceActions[entry.service] = entry.action
		}
		if entry.action != "none" {
			serviceReasons[entry.service] = append(serviceReasons[entry.service], d.RelPath)
		}
	}

	// Build output for all known services.
	allServices := []string{"postfix", "dovecot", "rspamd", "traefik"}
	var actions []ServiceAction
	for _, svc := range allServices {
		action := serviceActions[svc]
		if action == "" {
			action = "none"
		}
		sa := ServiceAction{
			Service: svc,
			Action:  action,
		}
		if reasons, ok := serviceReasons[svc]; ok {
			sa.Reason = strings.Join(reasons, ", ")
		}
		actions = append(actions, sa)
	}
	return actions
}

func actionPriority(action string) int {
	switch action {
	case "restart":
		return 3
	case "reload":
		return 2
	case "none", "":
		return 1
	default:
		return 0
	}
}

// ReloadResult records the outcome of a service reload/restart.
type ReloadResult struct {
	Service string `json:"service"`
	Action  string `json:"action"`
	Success bool   `json:"success"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ExecuteActions performs the reload/restart for each service that needs it.
func ExecuteActions(actions []ServiceAction) []ReloadResult {
	var results []ReloadResult

	for _, a := range actions {
		if a.Action == "none" {
			continue
		}

		container := "vectis-" + a.Service
		var cmd *exec.Cmd

		switch a.Service {
		case "postfix":
			if a.Action == "reload" {
				cmd = exec.Command("docker", "exec", container, "postfix", "reload")
			} else {
				cmd = exec.Command("docker", "restart", container)
			}
		case "dovecot":
			if a.Action == "reload" {
				cmd = exec.Command("docker", "exec", container, "doveadm", "reload")
			} else {
				cmd = exec.Command("docker", "restart", container)
			}
		case "rspamd":
			if a.Action == "reload" {
				cmd = exec.Command("docker", "kill", "--signal=HUP", container)
			} else {
				cmd = exec.Command("docker", "restart", container)
			}
		case "traefik":
			// Traefik watches config files; restart only if static config changed.
			cmd = exec.Command("docker", "restart", container)
		default:
			cmd = exec.Command("docker", "restart", container)
		}

		out, err := cmd.CombinedOutput()
		r := ReloadResult{
			Service: a.Service,
			Action:  a.Action,
			Output:  strings.TrimSpace(string(out)),
		}
		if err != nil {
			r.Success = false
			r.Error = fmt.Sprintf("%s: %s", err, string(out))
		} else {
			r.Success = true
		}
		results = append(results, r)
	}

	return results
}
