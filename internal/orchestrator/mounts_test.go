package orchestrator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckOrchestratorMounts_BothWritable(t *testing.T) {
	composeDir := t.TempDir()
	generatedDir := t.TempDir()

	composePath := filepath.Join(composeDir, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte("version: '3'"), 0o644); err != nil {
		t.Fatalf("seed compose: %v", err)
	}

	if issues := CheckOrchestratorMounts(composePath, generatedDir); len(issues) != 0 {
		t.Fatalf("expected no issues, got %v", issues)
	}
}

func TestCheckOrchestratorMounts_GeneratedDirMissing(t *testing.T) {
	composeDir := t.TempDir()
	composePath := filepath.Join(composeDir, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte("v"), 0o644); err != nil {
		t.Fatalf("seed compose: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "no-such-dir")

	issues := CheckOrchestratorMounts(composePath, missing)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d: %v", len(issues), issues)
	}
	if issues[0].Path != missing {
		t.Errorf("issue path = %q, want %q", issues[0].Path, missing)
	}
	if !strings.Contains(issues[0].Detail, "does not exist") {
		t.Errorf("issue detail %q should report 'does not exist'", issues[0].Detail)
	}
}

func TestCheckOrchestratorMounts_ComposeDirReadOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: filesystem perms ignored, skipping read-only probe")
	}
	composeDir := t.TempDir()
	composePath := filepath.Join(composeDir, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte("v"), 0o644); err != nil {
		t.Fatalf("seed compose: %v", err)
	}
	if err := os.Chmod(composeDir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(composeDir, 0o755) })

	generatedDir := t.TempDir()
	issues := CheckOrchestratorMounts(composePath, generatedDir)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d: %v", len(issues), issues)
	}
	if issues[0].Path != composeDir {
		t.Errorf("issue path = %q, want %q", issues[0].Path, composeDir)
	}
	if !strings.Contains(issues[0].Detail, "not writable") {
		t.Errorf("issue detail %q should report 'not writable'", issues[0].Detail)
	}
}

func TestMountIssuesRemediation_Empty(t *testing.T) {
	if got := MountIssuesRemediation(nil); got != "" {
		t.Errorf("empty issues should yield empty string, got %q", got)
	}
}

func TestMountIssuesRemediation_HasGuidance(t *testing.T) {
	issues := []MountIssue{
		{Path: "/etc/vectis", Detail: "not writable: read-only filesystem"},
	}
	got := MountIssuesRemediation(issues)
	if !strings.Contains(got, "/etc/vectis") {
		t.Errorf("remediation should mention the broken path, got %q", got)
	}
	if !strings.Contains(got, "Remediation") {
		t.Errorf("remediation block should be labelled, got %q", got)
	}
}
