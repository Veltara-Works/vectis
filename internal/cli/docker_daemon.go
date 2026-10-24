package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// defaultDockerDaemonJSON is written on a fresh install. It must stay in step
// with the heredoc in scripts/install.sh, which writes the same file when the
// one-line installer runs first.
//
// live-restore keeps containers running while dockerd/containerd restart for a
// package upgrade. Without it every container is stopped and restarted, and a
// container whose shutdown races the daemon's teardown can be left Exited (#311:
// rspamd, i.e. no DKIM signing or spam filtering until started by hand).
const defaultDockerDaemonJSON = `{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "5"
  },
  "ipv6": true,
  "fixed-cidr-v6": "fd00::/80",
  "ip6tables": true,
  "live-restore": true
}
`

type daemonConfigChange int

const (
	daemonConfigUnchanged daemonConfigChange = iota
	daemonConfigCreated                      // new file: needs a dockerd restart
	daemonConfigUpdated                      // live-restore added: a reload applies it
)

// ensureDockerDaemonConfig writes the default daemon.json when none exists, and
// otherwise adds "live-restore": true if the key is absent. It never changes an
// existing key, so an operator's explicit "live-restore": false is respected,
// and it leaves a file it cannot parse untouched.
func ensureDockerDaemonConfig(path string) (daemonConfigChange, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return daemonConfigUnchanged, err
		}
		if err := os.WriteFile(path, []byte(defaultDockerDaemonJSON), 0644); err != nil {
			return daemonConfigUnchanged, err
		}
		return daemonConfigCreated, nil
	}
	if err != nil {
		return daemonConfigUnchanged, err
	}

	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return daemonConfigUnchanged, fmt.Errorf("parse %s: %w", path, err)
	}
	if _, ok := cfg["live-restore"]; ok {
		return daemonConfigUnchanged, nil
	}
	cfg["live-restore"] = true
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return daemonConfigUnchanged, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return daemonConfigUnchanged, err
	}
	if err := os.WriteFile(path, append(out, '\n'), info.Mode().Perm()); err != nil {
		return daemonConfigUnchanged, err
	}
	return daemonConfigUpdated, nil
}
