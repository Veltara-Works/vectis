package cli

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var preflightCmd = &cobra.Command{
	Use:   "preflight",
	Short: "Run pre-flight checks before installation",
	Long:  `Validates the host environment without making any changes.`,
	RunE:  runPreflight,
}

type checkResult struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // "pass", "fail", "warn"
	Value   string `json:"value"`
	Message string `json:"message,omitempty"`
}

func runPreflight(cmd *cobra.Command, args []string) error {
	fmt.Fprintln(cmd.OutOrStdout(), "Vectis Pre-Flight Check")
	fmt.Fprintln(cmd.OutOrStdout(), "=======================")

	var checks []checkResult
	failed := 0

	// OS check
	checks = append(checks, checkOS())

	// CPU check
	checks = append(checks, checkCPU())

	// RAM check
	checks = append(checks, checkRAM())

	// Disk check
	checks = append(checks, checkDisk())

	// Port checks
	for _, port := range []int{25, 80, 443, 465, 587, 993, 995} {
		checks = append(checks, checkPort(port))
	}

	// Docker check
	checks = append(checks, checkDocker())

	// Print results
	for _, c := range checks {
		icon := "✓"
		if c.Status == "fail" {
			icon = "✗"
			failed++
		} else if c.Status == "warn" {
			icon = "!"
		}

		line := fmt.Sprintf("%-14s %-28s %s", c.Name+":", c.Value, icon)
		if c.Message != "" {
			line += " " + c.Message
		}
		fmt.Fprintln(cmd.OutOrStdout(), line)
	}

	fmt.Fprintln(cmd.OutOrStdout())
	if failed > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "%d check(s) failed. Fix the above issues before installing.\n", failed)
		os.Exit(1)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Ready to install Vectis.")
	fmt.Fprintln(cmd.OutOrStdout(), "Run: vectis install")
	return nil
}

func checkOS() checkResult {
	out, err := exec.Command("lsb_release", "-ds").Output()
	if err != nil {
		return checkResult{Name: "OS", Status: "warn", Value: runtime.GOOS, Message: "Could not detect OS version"}
	}
	osName := strings.TrimSpace(string(out))
	if strings.Contains(osName, "Ubuntu") && (strings.Contains(osName, "24.04") || strings.Contains(osName, "22.04")) {
		return checkResult{Name: "OS", Status: "pass", Value: osName}
	}
	return checkResult{Name: "OS", Status: "warn", Value: osName, Message: "Ubuntu 24.04 LTS recommended"}
}

func checkCPU() checkResult {
	cpus := runtime.NumCPU()
	if cpus >= 2 {
		return checkResult{Name: "CPU", Status: "pass", Value: fmt.Sprintf("%d vCPU", cpus)}
	}
	return checkResult{Name: "CPU", Status: "warn", Value: fmt.Sprintf("%d vCPU", cpus), Message: "Minimum 2 vCPU recommended"}
}

func checkRAM() checkResult {
	out, err := exec.Command("awk", "/MemTotal/{print $2}", "/proc/meminfo").Output()
	if err != nil {
		return checkResult{Name: "RAM", Status: "warn", Value: "unknown"}
	}
	kb, _ := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	gb := kb / 1024 / 1024
	if gb >= 4 {
		return checkResult{Name: "RAM", Status: "pass", Value: fmt.Sprintf("%d GB", gb)}
	}
	if gb >= 2 {
		return checkResult{Name: "RAM", Status: "warn", Value: fmt.Sprintf("%d GB", gb), Message: "4 GB recommended (2 GB minimum without ClamAV)"}
	}
	return checkResult{Name: "RAM", Status: "fail", Value: fmt.Sprintf("%d GB", gb), Message: "Minimum 2 GB required"}
}

func checkDisk() checkResult {
	out, err := exec.Command("df", "-BG", "--output=avail", "/").Output()
	if err != nil {
		return checkResult{Name: "Disk", Status: "warn", Value: "unknown"}
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return checkResult{Name: "Disk", Status: "warn", Value: "unknown"}
	}
	avail := strings.TrimSuffix(strings.TrimSpace(lines[1]), "G")
	gb, _ := strconv.ParseInt(avail, 10, 64)
	if gb >= 20 {
		return checkResult{Name: "Disk", Status: "pass", Value: fmt.Sprintf("%d GB free", gb)}
	}
	return checkResult{Name: "Disk", Status: "fail", Value: fmt.Sprintf("%d GB free", gb), Message: "Minimum 20 GB free required"}
}

func checkPort(port int) checkResult {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return checkResult{
			Name:    fmt.Sprintf("Port %d", port),
			Status:  "fail",
			Value:   "in use",
			Message: fmt.Sprintf("Stop the process using port %d", port),
		}
	}
	ln.Close()
	return checkResult{Name: fmt.Sprintf("Port %d", port), Status: "pass", Value: "available"}
}

func checkDocker() checkResult {
	out, err := exec.Command("docker", "--version").Output()
	if err != nil {
		return checkResult{Name: "Docker", Status: "pass", Value: "not installed", Message: "(will be installed)"}
	}
	ver := strings.TrimSpace(string(out))

	// Also check compose
	_, err = exec.Command("docker", "compose", "version").Output()
	if err != nil {
		return checkResult{Name: "Docker", Status: "warn", Value: ver, Message: "Docker Compose not found"}
	}
	return checkResult{Name: "Docker", Status: "pass", Value: ver}
}

func init() {
	RootCmd.AddCommand(preflightCmd)
}
