package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docker kill --signal=HUP cancels the restart policy for the container's next
// exit, so reloads must go through docker exec (#334).
func TestExecuteActions_ReloadsNeverUseDockerKill(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\necho \"$*\" >> \"$STUB_LOG\"\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("STUB_LOG", log)

	results := ExecuteActions([]ServiceAction{
		{Service: "postfix", Action: "reload"},
		{Service: "dovecot", Action: "reload"},
		{Service: "rspamd", Action: "reload"},
	})
	for _, r := range results {
		if !r.Success {
			t.Errorf("%s: %s", r.Service, r.Error)
		}
	}

	got, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	want := "exec vectis-postfix postfix reload\nexec vectis-dovecot doveadm reload\nexec vectis-rspamd kill -HUP 1\n"
	if string(got) != want {
		t.Errorf("docker calls:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(string(got), "--signal") {
		t.Error("reloads must not use docker kill")
	}
}
