package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// stubDockerInspect puts a fake `docker` first on PATH: it prints stdout and
// stderr and exits rc, and records that it ran in the returned path.
func stubDockerInspect(t *testing.T, stdout, stderr, rc string) string {
	t.Helper()
	dir := t.TempDir()
	called := filepath.Join(dir, "called")
	script := "#!/bin/sh\necho \"$*\" >> \"$STUB_CALLED\"\nprintf '%s' \"$STUB_OUT\"\nprintf '%s' \"$STUB_ERR\" >&2\nexit \"$STUB_RC\"\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("STUB_CALLED", called)
	t.Setenv("STUB_OUT", stdout)
	t.Setenv("STUB_ERR", stderr)
	t.Setenv("STUB_RC", rc)
	return called
}

func TestCLIDBHost(t *testing.T) {
	t.Run("host side: docker names the container's address", func(t *testing.T) {
		stubDockerInspect(t, "172.22.0.2 \n", "", "0")
		if got := cliDBHost("postgres"); got != "172.22.0.2" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("container not there: keep the service name", func(t *testing.T) {
		stubDockerInspect(t, "", "error: no such object: vectis-postgres", "1")
		if got := cliDBHost("postgres"); got != "postgres" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("container stopped (no address): keep the service name", func(t *testing.T) {
		stubDockerInspect(t, " \n", "", "0")
		if got := cliDBHost("postgres"); got != "postgres" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("inside a container (no docker binary): keep the service name", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if got := cliDBHost("postgres"); got != "postgres" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("custom database host: left alone, docker not asked", func(t *testing.T) {
		called := stubDockerInspect(t, "172.22.0.2", "", "0")
		if got := cliDBHost("db.internal.example"); got != "db.internal.example" {
			t.Errorf("got %q", got)
		}
		if _, err := os.Stat(called); err == nil {
			t.Error("docker must not be consulted for a custom host")
		}
	})
}

// Docker 29 changed `docker inspect` on a missing container from
// "Error: No such object: x" to "error: no such object: x". Either way it means
// not deployed: an optional service is skipped and a core one FAILs. Reading it
// as a docker error made every default install UNVERIFIABLE.
func TestDockerContainerImage_MissingContainer(t *testing.T) {
	for _, msg := range []string{
		"error: no such object: vectis-clamav\n",
		"Error: No such object: vectis-clamav\n",
	} {
		stubDockerInspect(t, "", msg, "1")
		ci, err := dockerContainerImage("vectis-clamav")
		if err != nil {
			t.Fatalf("%q: a missing container is not an error: %v", msg, err)
		}
		if ci.Present {
			t.Errorf("%q: must report not present", msg)
		}
	}

	stubDockerInspect(t, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock.\n", "1")
	if _, err := dockerContainerImage("vectis-clamav"); err == nil {
		t.Error("a daemon failure must stay an error (unverifiable), not read as missing")
	}
}
