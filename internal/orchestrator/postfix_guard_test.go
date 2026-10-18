package orchestrator

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// stubDocker puts a fake `docker` first on PATH. `docker inspect` prints
// STUB_INSPECT_OUT and exits STUB_INSPECT_RC; `docker exec … postqueue -j`
// prints STUB_QUEUE_OUT and exits STUB_QUEUE_RC; every call is appended to the
// returned log file.
func stubDocker(t *testing.T, inspectOut string, inspectRC int, queueOut string, queueRC int) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	script := `#!/bin/sh
echo "$*" >> "$STUB_LOG"
case "$1" in
inspect) printf '%s' "$STUB_INSPECT_OUT"; exit "$STUB_INSPECT_RC" ;;
exec)
  case "$*" in
  *"postqueue -j"*) printf '%s' "$STUB_QUEUE_OUT"; exit "$STUB_QUEUE_RC" ;;
  *) exit 0 ;;
  esac ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("STUB_LOG", log)
	t.Setenv("STUB_INSPECT_OUT", inspectOut)
	t.Setenv("STUB_INSPECT_RC", strconv.Itoa(inspectRC))
	t.Setenv("STUB_QUEUE_OUT", queueOut)
	t.Setenv("STUB_QUEUE_RC", strconv.Itoa(queueRC))
	return log
}

func calls(t *testing.T, log string) string {
	t.Helper()
	b, _ := os.ReadFile(log)
	return string(b)
}

const oneQueued = `{"queue_name": "deferred", "queue_id": "E6D7E12CEDF", "recipients": [{"address": "zz@[192.0.2.1]"}]}` + "\n"

// The branches of guardPostfixQueue (#298) protect accepted mail across a
// postfix recreate (Copilot, #299).
func TestGuardPostfixQueue(t *testing.T) {
	dm := &DockerManager{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()

	t.Run("spool mounted: no drain", func(t *testing.T) {
		log := stubDocker(t, "mounted", 0, oneQueued, 0)
		if err := dm.guardPostfixQueue(ctx, 0); err != nil {
			t.Fatal(err)
		}
		if c := calls(t, log); strings.Contains(c, "postqueue") {
			t.Errorf("a mounted spool must not be drained; calls:\n%s", c)
		}
	})

	t.Run("no spool mount, empty queue: allowed", func(t *testing.T) {
		stubDocker(t, "", 0, "", 0)
		if err := dm.guardPostfixQueue(ctx, 0); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("no spool mount, mail queued: flushed, then refused", func(t *testing.T) {
		log := stubDocker(t, "", 0, oneQueued, 0)
		err := dm.guardPostfixQueue(ctx, 0)
		if err == nil || !strings.Contains(err.Error(), "1 message(s) still in the Postfix queue") {
			t.Fatalf("err = %v", err)
		}
		if c := calls(t, log); !strings.Contains(c, "postqueue -f") {
			t.Errorf("expected a flush before refusing; calls:\n%s", c)
		}
	})

	t.Run("no spool mount, postfix stopped: refused", func(t *testing.T) {
		stubDocker(t, "", 0, "Error response from daemon: container abc is not running", 1)
		if err := dm.guardPostfixQueue(ctx, 0); err == nil || !strings.Contains(err.Error(), "isn't running") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("no postfix container: allowed", func(t *testing.T) {
		log := stubDocker(t, "Error: No such object: vectis-postfix", 1, "", 0)
		if err := dm.guardPostfixQueue(ctx, 0); err != nil {
			t.Fatal(err)
		}
		if c := calls(t, log); strings.Contains(c, "postqueue") {
			t.Errorf("no container, nothing to drain; calls:\n%s", c)
		}
	})

	t.Run("inspect fails otherwise: refused", func(t *testing.T) {
		stubDocker(t, "permission denied while trying to connect to the Docker daemon socket", 1, "", 0)
		if err := dm.guardPostfixQueue(ctx, 0); err == nil || !strings.Contains(err.Error(), "inspect postfix mounts") {
			t.Fatalf("err = %v", err)
		}
	})
}
