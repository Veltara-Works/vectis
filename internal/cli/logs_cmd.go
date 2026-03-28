package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/spf13/cobra"
)

var logsCmd = &cobra.Command{
	Use:   "logs [service]",
	Short: "Show logs for a Vectis service",
	Long: `Show logs for a specific Vectis service.

Available services: postfix, dovecot, rspamd, clamav, postgres, valkey, api, traefik`,
	Args: cobra.ExactArgs(1),
	RunE: runLogs,
}

var (
	logsTail   int
	logsSince  string
	logsFollow bool
)

var validLogServices = map[string]string{
	"postfix":  "vectis-postfix",
	"dovecot":  "vectis-dovecot",
	"rspamd":   "vectis-rspamd",
	"clamav":   "vectis-clamav",
	"postgres": "vectis-postgres",
	"valkey":   "vectis-valkey",
	"api":      "vectis-api",
	"traefik":  "vectis-traefik",
}

func runLogs(cmd *cobra.Command, args []string) error {
	service := args[0]
	container, ok := validLogServices[service]
	if !ok {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: unknown service %q\n", service)
		fmt.Fprintln(cmd.ErrOrStderr(), "Available: postfix, dovecot, rspamd, clamav, postgres, valkey, api, traefik")
		os.Exit(2)
	}

	dockerArgs := []string{"logs"}
	if logsTail > 0 {
		dockerArgs = append(dockerArgs, "--tail", strconv.Itoa(logsTail))
	}
	if logsSince != "" {
		dockerArgs = append(dockerArgs, "--since", logsSince)
	}
	if logsFollow {
		dockerArgs = append(dockerArgs, "--follow")
	}
	dockerArgs = append(dockerArgs, container)

	dockerCmd := exec.Command("docker", dockerArgs...)
	dockerCmd.Stdout = cmd.OutOrStdout()
	dockerCmd.Stderr = cmd.ErrOrStderr()

	return dockerCmd.Run()
}

func init() {
	logsCmd.Flags().IntVar(&logsTail, "tail", 100, "Number of lines to show")
	logsCmd.Flags().StringVar(&logsSince, "since", "", "Show logs since timestamp (e.g., 2026-03-28, 1h, 30m)")
	logsCmd.Flags().BoolVarP(&logsFollow, "follow", "f", false, "Follow log output")

	RootCmd.AddCommand(logsCmd)
}
