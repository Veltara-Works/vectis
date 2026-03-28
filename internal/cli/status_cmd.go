package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show status of all Vectis services",
	RunE:  runStatus,
}

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Show detailed health of Vectis services",
	RunE:  runHealth,
}

var healthService string

type serviceStatus struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Health   string `json:"health,omitempty"`
	Uptime   string `json:"uptime,omitempty"`
	Ports    string `json:"ports,omitempty"`
}

var vectisServices = []string{
	"vectis-postfix",
	"vectis-dovecot",
	"vectis-rspamd",
	"vectis-postgres",
	"vectis-valkey",
	"vectis-traefik",
}

func runStatus(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")

	statuses, unhealthy := getServiceStatuses()

	if jsonOutput {
		out, _ := json.MarshalIndent(statuses, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "Vectis Status")
		fmt.Fprintln(cmd.OutOrStdout(), "═════════════")
		fmt.Fprintf(cmd.OutOrStdout(), "%-16s %-12s %-16s %s\n", "Service", "Status", "Health", "Uptime")
		fmt.Fprintln(cmd.OutOrStdout(), "────────────────────────────────────────────────────────")
		for _, s := range statuses {
			fmt.Fprintf(cmd.OutOrStdout(), "%-16s %-12s %-16s %s\n",
				s.Name, s.Status, s.Health, s.Uptime)
		}
	}

	if unhealthy > 0 {
		os.Exit(1)
	}
	return nil
}

func runHealth(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")

	services := vectisServices
	if healthService != "" {
		services = []string{"vectis-" + healthService}
	}

	type healthDetail struct {
		Name       string `json:"name"`
		Status     string `json:"status"`
		Health     string `json:"health"`
		Image      string `json:"image,omitempty"`
		Ports      string `json:"ports,omitempty"`
		Uptime     string `json:"uptime,omitempty"`
		RestartCnt string `json:"restart_count,omitempty"`
	}

	var details []healthDetail
	unhealthy := 0

	for _, svc := range services {
		d := healthDetail{Name: strings.TrimPrefix(svc, "vectis-")}

		out, err := exec.Command("docker", "inspect", "--format",
			`{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.Config.Image}}|{{.State.StartedAt}}|{{.RestartCount}}`,
			svc).Output()
		if err != nil {
			d.Status = "not found"
			d.Health = "unknown"
			unhealthy++
			details = append(details, d)
			continue
		}

		parts := strings.Split(strings.TrimSpace(string(out)), "|")
		if len(parts) >= 5 {
			d.Status = parts[0]
			d.Health = parts[1]
			if d.Health == "" {
				d.Health = "no healthcheck"
			}
			d.Image = parts[2]
			d.RestartCnt = parts[4]

			if startedAt, err := time.Parse(time.RFC3339Nano, parts[3]); err == nil {
				d.Uptime = formatUptime(time.Since(startedAt))
			}
		}

		// Get ports
		portOut, _ := exec.Command("docker", "port", svc).Output()
		if len(portOut) > 0 {
			lines := strings.Split(strings.TrimSpace(string(portOut)), "\n")
			var portParts []string
			for _, l := range lines {
				if p := strings.Split(l, " -> "); len(p) == 2 {
					portParts = append(portParts, strings.Split(p[0], "/")[0])
				}
			}
			d.Ports = strings.Join(portParts, ", ")
		}

		if d.Health != "healthy" && d.Health != "no healthcheck" {
			unhealthy++
		}

		details = append(details, d)
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(details, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else {
		for _, d := range details {
			icon := "✓"
			if d.Health == "unhealthy" || d.Status == "not found" {
				icon = "✗"
			} else if d.Health == "starting" {
				icon = "…"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %-12s status=%-10s health=%-12s uptime=%-12s restarts=%s\n",
				icon, d.Name, d.Status, d.Health, d.Uptime, d.RestartCnt)
			if d.Ports != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "  ports: %s\n", d.Ports)
			}
		}
	}

	if unhealthy > 0 {
		os.Exit(1)
	}
	return nil
}

func getServiceStatuses() ([]serviceStatus, int) {
	var statuses []serviceStatus
	unhealthy := 0

	for _, svc := range vectisServices {
		s := serviceStatus{Name: strings.TrimPrefix(svc, "vectis-")}

		out, err := exec.Command("docker", "inspect", "--format",
			`{{.State.Status}}|{{.State.Health.Status}}|{{.State.StartedAt}}`,
			svc).Output()
		if err != nil {
			s.Status = "not found"
			s.Health = "unknown"
			unhealthy++
			statuses = append(statuses, s)
			continue
		}

		parts := strings.Split(strings.TrimSpace(string(out)), "|")
		if len(parts) >= 3 {
			s.Status = parts[0]
			s.Health = parts[1]
			if s.Health == "" {
				s.Health = "-"
			}

			if startedAt, err := time.Parse(time.RFC3339Nano, parts[2]); err == nil {
				s.Uptime = formatUptime(time.Since(startedAt))
			}
		}

		if s.Health == "unhealthy" {
			unhealthy++
		}

		statuses = append(statuses, s)
	}

	return statuses, unhealthy
}

func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}

func init() {
	healthCmd.Flags().StringVar(&healthService, "service", "", "Show health for a specific service")
	RootCmd.AddCommand(statusCmd)
	RootCmd.AddCommand(healthCmd)
}
