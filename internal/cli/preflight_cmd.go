package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

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

	// Outbound SMTP check
	checks = append(checks, checkOutboundSMTP())

	// Docker check
	checks = append(checks, checkDocker())

	// Existing secrets.yaml must not hold public dev/example credentials.
	configDir, _ := cmd.Flags().GetString("config-dir")
	checks = append(checks, checkSecretsDefaults(filepath.Join(configDir, "secrets.yaml")))

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
	return ramResult(kb)
}

// ramResult grades MemTotal (kB). A VPS sold as 4 GB shows the kernel about
// 3.8 GiB (firmware and kernel reservations), and a 2 GB one about 1.9 GiB, so
// whole-GiB integer division read them as "3 GB" (warn) and "1 GB" (fail). The
// thresholds allow for that reservation, and the value is shown to one decimal.
func ramResult(kb int64) checkResult {
	mib := kb / 1024
	val := fmt.Sprintf("%.1f GB", float64(kb)/1024/1024)
	switch {
	case mib >= 3584: // a 4 GB plan
		return checkResult{Name: "RAM", Status: "pass", Value: val}
	case mib >= 1792: // a 2 GB plan
		return checkResult{Name: "RAM", Status: "warn", Value: val, Message: "4 GB recommended (2 GB minimum without ClamAV)"}
	}
	return checkResult{Name: "RAM", Status: "fail", Value: val, Message: "Minimum 2 GB required"}
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

// port25GuideURL explains the outbound port 25 block per VPS provider.
const port25GuideURL = "https://vectismail.com/guides/port-25-blocked/"

// smtpProbeHost is a large mail server that always listens on port 25.
const smtpProbeHost = "gmail-smtp-in.l.google.com"

func checkOutboundSMTP() checkResult {
	// Test outbound port 25 by connecting to a well-known SMTP server.
	conn, err := net.DialTimeout("tcp", smtpProbeHost+":25", 10*time.Second)
	if err != nil {
		return outboundSMTPFailure(err)
	}
	conn.Close()
	return checkResult{Name: "SMTP out", Status: "pass", Value: "port 25 reachable"}
}

// outboundSMTPFailure says why the port 25 probe failed. A failed DNS lookup
// says nothing about port 25, so it gets its own message; any other failure
// (a timeout, typically) is most often the provider's block, but a local
// firewall looks the same, so the reason is shown alongside the guide link.
func outboundSMTPFailure(err error) checkResult {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return checkResult{
			Name:    "SMTP out",
			Status:  "warn",
			Value:   "not checked",
			Message: "Could not look up " + smtpProbeHost + ": check this server's DNS, then re-run",
		}
	}
	reason := "Connection timed out"
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		reason = err.Error()
		if i := strings.LastIndex(reason, ": "); i >= 0 {
			reason = reason[i+2:] // "dial tcp …:25: connect: connection refused" → "connection refused"
		}
		if reason != "" {
			reason = strings.ToUpper(reason[:1]) + reason[1:]
		}
	}
	return checkResult{
		Name:    "SMTP out",
		Status:  "warn",
		Value:   "port 25 blocked",
		Message: reason + ". Usually the provider blocks it (or check this server's firewall): " + port25GuideURL,
	}
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
