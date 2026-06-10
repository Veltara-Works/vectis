package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestCollectRenderedConfigs(t *testing.T) {
	root := t.TempDir()

	// docker-compose.yml at root must be excluded (owned by RegenerateCompose).
	mustWrite(t, filepath.Join(root, "docker-compose.yml"), "services: {}\n", 0o644)
	// Per-service configs at various depths.
	mustWrite(t, filepath.Join(root, "postfix", "main.cf"), "myhostname = mail\n", 0o644)
	mustWrite(t, filepath.Join(root, "rspamd", "local.lua"), "-- lua\n", 0o600)
	// Executable shell script — its 0755 bit must survive.
	mustWrite(t, filepath.Join(root, "postgres", "init-users.sh"), "#!/bin/sh\n", 0o755)

	got, err := collectRenderedConfigs(root)
	if err != nil {
		t.Fatalf("collectRenderedConfigs: %v", err)
	}

	byPath := map[string]ConfigFile{}
	for _, f := range got {
		byPath[f.RelPath] = f
	}

	if _, ok := byPath["docker-compose.yml"]; ok {
		t.Error("docker-compose.yml must NOT be returned as a config file")
	}

	want := []string{"postfix/main.cf", "postgres/init-users.sh", "rspamd/local.lua"}
	gotPaths := make([]string, 0, len(byPath))
	for p := range byPath {
		gotPaths = append(gotPaths, p)
	}
	sort.Strings(gotPaths)
	if len(gotPaths) != len(want) {
		t.Fatalf("rel paths = %v, want %v", gotPaths, want)
	}
	for i := range want {
		if gotPaths[i] != want[i] {
			t.Errorf("rel path[%d] = %q, want %q", i, gotPaths[i], want[i])
		}
	}

	// Mode preservation: the shell script keeps its exec bit, the others don't.
	if m := byPath["postgres/init-users.sh"].Mode; m&0o111 == 0 {
		t.Errorf("init-users.sh mode = %o, expected an exec bit set", m)
	}
	if m := byPath["postfix/main.cf"].Mode; m&0o111 != 0 {
		t.Errorf("main.cf mode = %o, expected no exec bit", m)
	}
	if string(byPath["postfix/main.cf"].Content) != "myhostname = mail\n" {
		t.Errorf("main.cf content mismatch: %q", string(byPath["postfix/main.cf"].Content))
	}
}

func TestCollectRenderedConfigs_OnlyCompose(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "docker-compose.yml"), "services: {}\n", 0o644)

	got, err := collectRenderedConfigs(root)
	if err != nil {
		t.Fatalf("collectRenderedConfigs: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no config files when only compose present, got %d", len(got))
	}
}

func TestStaticComposeGenerator(t *testing.T) {
	gen := staticComposeGenerator([]byte("compose-bytes"))
	out, err := gen(context.Background(), "v9.9.9")
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if string(out) != "compose-bytes" {
		t.Errorf("got %q", string(out))
	}

	// Empty content is a programming error and must surface, not silently
	// regenerate an empty compose (which RegenerateCompose would reject anyway).
	if _, err := staticComposeGenerator(nil)(context.Background(), ""); err == nil {
		t.Error("expected error for empty static compose content")
	}
}

func TestStaticConfigGenerator(t *testing.T) {
	files := []ConfigFile{{RelPath: "postfix/main.cf", Content: []byte("x")}}
	out, err := staticConfigGenerator(files)(context.Background(), "")
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if len(out) != 1 || out[0].RelPath != "postfix/main.cf" {
		t.Errorf("got %+v", out)
	}
}

func TestSanitizeForPath(t *testing.T) {
	cases := map[string]string{
		"":                                     "render",
		"0190c6f2-1234-7abc-def0-112233445566": "0190c6f2-1234-7abc-def0-112233445566",
		// Slashes are stripped (no traversal possible); dots are kept so version
		// tags like v0.1.25 survive — harmless once separators are gone.
		"job/../../etc/passwd": "job-..-..-etc-passwd",
		"a b\tc":               "a-b-c",
		"keep.dot_and-dash":    "keep.dot_and-dash",
		"v0.1.25":              "v0.1.25",
	}
	for in, want := range cases {
		if got := sanitizeForPath(in); got != want {
			t.Errorf("sanitizeForPath(%q) = %q, want %q", in, got, want)
		}
	}
	// No path separators must ever survive — scratch must stay a single segment.
	if got := sanitizeForPath("a/b/c"); filepath.Base(got) != got {
		t.Errorf("sanitizeForPath left a path separator: %q", got)
	}
}

func TestPickRenderNetwork(t *testing.T) {
	if got := pickRenderNetwork(map[string]bool{}); got != "" {
		t.Errorf("empty set = %q, want \"\"", got)
	}
	// Deterministic smallest among user-defined networks.
	got := pickRenderNetwork(map[string]bool{"vectis-frontend": true, "vectis-data": true, "vectis-orchestrator": true})
	if got != "vectis-data" {
		t.Errorf("pickRenderNetwork = %q, want vectis-data", got)
	}
	// Built-in networks must be skipped even though "bridge" sorts first.
	got = pickRenderNetwork(map[string]bool{"bridge": true, "host": true, "none": true, "vectis-data": true})
	if got != "vectis-data" {
		t.Errorf("pickRenderNetwork with built-ins = %q, want vectis-data", got)
	}
	// Only built-ins → nothing usable.
	if got := pickRenderNetwork(map[string]bool{"bridge": true, "host": true}); got != "" {
		t.Errorf("pickRenderNetwork builtins-only = %q, want \"\"", got)
	}
}

func TestCollectRenderedConfigs_SkipsSymlinks(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "postfix", "main.cf"), "ok\n", 0o644)
	// A symlink pointing outside the scratch dir must NOT be read/followed.
	secret := filepath.Join(t.TempDir(), "host-secret")
	mustWrite(t, secret, "TOPSECRET\n", 0o600)
	if err := os.Symlink(secret, filepath.Join(root, "evil.cf")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	got, err := collectRenderedConfigs(root)
	if err != nil {
		t.Fatalf("collectRenderedConfigs: %v", err)
	}
	for _, f := range got {
		if f.RelPath == "evil.cf" {
			t.Fatalf("symlink was followed/included: %q -> %q", f.RelPath, string(f.Content))
		}
	}
	if len(got) != 1 || got[0].RelPath != "postfix/main.cf" {
		t.Errorf("expected only postfix/main.cf, got %+v", got)
	}
}

func mustWrite(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile is umask-masked; force the exact mode so the exec-bit assertion is reliable.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
