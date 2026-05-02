package orchestrator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MountIssue describes a mount-probe failure that prevents self-heal or
// Apply from running correctly. Surfaced verbatim in logs and Apply error
// messages so operators can act on it without reading the source.
type MountIssue struct {
	Path   string
	Detail string
}

// String renders a one-line diagnostic.
func (m MountIssue) String() string {
	return fmt.Sprintf("%s: %s", m.Path, m.Detail)
}

// CheckOrchestratorMounts probes the two host paths the orchestrator must
// be able to write through during Apply and self-heal:
//
//   - The directory containing composePath (must be RW so Phase 3.5 can
//     atomically rewrite docker-compose.yml).
//   - generatedDir (must be RW so RegenerateConfigs can write per-service
//     config files for postfix/dovecot/rspamd/etc).
//
// Pre-v0.1.5 templates mounted /etc/vectis as :ro and didn't mount
// /var/vectis/generated at all. Orchestrator containers created from those
// templates can't perform self-heal or Apply — see
// feedback_v0.1.5_selfheal_legacy_install_broken.md. This helper lets the
// orchestrator detect the situation rather than failing silently mid-Apply.
//
// Returns nil when both paths are writable. Otherwise returns one issue per
// broken path (best-effort: never returns an error itself; the result is
// the diagnosis).
func CheckOrchestratorMounts(composePath, generatedDir string) []MountIssue {
	var issues []MountIssue
	composeDir := filepath.Dir(composePath)
	if err := probeWritableDir(composeDir); err != nil {
		issues = append(issues, MountIssue{Path: composeDir, Detail: err.Error()})
	}
	if err := probeWritableDir(generatedDir); err != nil {
		issues = append(issues, MountIssue{Path: generatedDir, Detail: err.Error()})
	}
	return issues
}

// MountIssuesRemediation returns a ready-to-print remediation block that
// callers can include in logs or API error responses. The orchestrator
// container needs to be recreated against the v0.1.6 template — there's
// no in-place fix possible (mounts are fixed at container creation).
func MountIssuesRemediation(issues []MountIssue) string {
	if len(issues) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("orchestrator container is missing required bind mounts:\n")
	for _, i := range issues {
		fmt.Fprintf(&b, "  - %s\n", i)
	}
	b.WriteString("\nRemediation: recreate the orchestrator container against the v0.1.6 template, which mounts /etc/vectis (rw) and /var/vectis/generated (rw). The recovery recipe is `docker compose -f /etc/vectis/docker-compose.yml up -d --force-recreate orchestrator` after rendering compose from v0.1.6 templates (e.g. via cmd/render-configs).")
	return b.String()
}

func probeWritableDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("does not exist (mount missing or empty)")
		}
		return fmt.Errorf("not accessible: %v", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("not a directory")
	}
	f, err := os.CreateTemp(dir, ".vectis-mount-probe-*")
	if err != nil {
		return fmt.Errorf("not writable: %v", err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}
