package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readDaemonJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("daemon.json is not valid JSON: %v\n%s", err, raw)
	}
	return m
}

func TestEnsureDockerDaemonConfigCreates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "docker", "daemon.json")
	change, err := ensureDockerDaemonConfig(path)
	if err != nil || change != daemonConfigCreated {
		t.Fatalf("change=%v err=%v, want created", change, err)
	}
	m := readDaemonJSON(t, path)
	for _, k := range []string{"log-driver", "log-opts", "ipv6", "fixed-cidr-v6", "ip6tables"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing %q", k)
		}
	}
	if m["live-restore"] != true {
		t.Errorf("live-restore = %v, want true", m["live-restore"])
	}
}

// The default must match what scripts/install.sh writes, key for key.
func TestDefaultDockerDaemonJSONMatchesInstallScript(t *testing.T) {
	script, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(script), `cat > "$DAEMON_JSON" <<'EOF'`)
	if start < 0 {
		t.Fatal("daemon.json heredoc not found in scripts/install.sh")
	}
	body := string(script[start:])
	body = body[strings.Index(body, "\n")+1:]
	body = body[:strings.Index(body, "\nEOF\n")+1]
	var fromScript, fromGo map[string]any
	if err := json.Unmarshal([]byte(body), &fromScript); err != nil {
		t.Fatalf("install.sh heredoc is not valid JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(defaultDockerDaemonJSON), &fromGo); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(fromScript)
	b, _ := json.Marshal(fromGo)
	if string(a) != string(b) {
		t.Fatalf("install.sh daemon.json %s != Go default %s", a, b)
	}
}

func TestEnsureDockerDaemonConfigAddsLiveRestore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.json")
	orig := `{"ipv6": true, "fixed-cidr-v6": "fd00::/80", "registry-mirrors": ["https://mirror.example"]}`
	if err := os.WriteFile(path, []byte(orig), 0600); err != nil {
		t.Fatal(err)
	}
	change, err := ensureDockerDaemonConfig(path)
	if err != nil || change != daemonConfigUpdated {
		t.Fatalf("change=%v err=%v, want updated", change, err)
	}
	m := readDaemonJSON(t, path)
	if m["live-restore"] != true || m["ipv6"] != true || m["fixed-cidr-v6"] != "fd00::/80" {
		t.Fatalf("unexpected result: %v", m)
	}
	if mirrors, _ := m["registry-mirrors"].([]any); len(mirrors) != 1 {
		t.Fatalf("operator key lost: %v", m)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0600 {
		t.Fatalf("mode changed to %v", info.Mode().Perm())
	}
}

func TestEnsureDockerDaemonConfigRespectsExplicitFalse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.json")
	orig := "{\n  \"live-restore\": false\n}\n"
	if err := os.WriteFile(path, []byte(orig), 0644); err != nil {
		t.Fatal(err)
	}
	change, err := ensureDockerDaemonConfig(path)
	if err != nil || change != daemonConfigUnchanged {
		t.Fatalf("change=%v err=%v, want unchanged", change, err)
	}
	if got, _ := os.ReadFile(path); string(got) != orig {
		t.Fatalf("file rewritten: %q", got)
	}
}

func TestEnsureDockerDaemonConfigLeavesInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.json")
	orig := "{ not json"
	if err := os.WriteFile(path, []byte(orig), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureDockerDaemonConfig(path); err == nil {
		t.Fatal("want a parse error")
	}
	if got, _ := os.ReadFile(path); string(got) != orig {
		t.Fatalf("file rewritten: %q", got)
	}
}
