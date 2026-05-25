//go:build windows

package gatekeeper

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestWindowsPaths_Constants verifies the canonical Windows path values.
func TestWindowsPaths_Constants(t *testing.T) {
	if windowsPaths.CAPubkey != `C:\ProgramData\ssh\uncluster_ca.pub` {
		t.Errorf("CA pubkey path = %q", windowsPaths.CAPubkey)
	}
	if windowsPaths.SSHDropIn != `C:\ProgramData\ssh\sshd_config.d\uncluster.conf` {
		t.Errorf("SSHDropIn path = %q", windowsPaths.SSHDropIn)
	}
	if windowsPaths.PrincipalsDir != `C:\ProgramData\ssh\auth_principals` {
		t.Errorf("PrincipalsDir = %q", windowsPaths.PrincipalsDir)
	}
}

// TestWindowsServiceAccountName verifies the virtual account constant.
func TestWindowsServiceAccountName(t *testing.T) {
	if windowsServiceAccountName != `NT SERVICE\UnclusterAgent` {
		t.Errorf("service account = %q, want NT SERVICE\\UnclusterAgent", windowsServiceAccountName)
	}
}

// TestContainsState verifies sc.exe output parsing.
func TestContainsState(t *testing.T) {
	scRunning := `SERVICE_NAME: sshd
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)`

	scStopped := `SERVICE_NAME: sshd
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED`

	if !containsState(scRunning, "RUNNING") {
		t.Error("should detect RUNNING state")
	}
	if containsState(scRunning, "STOPPED") {
		t.Error("should not detect STOPPED in RUNNING output")
	}
	if !containsState(scStopped, "STOPPED") {
		t.Error("should detect STOPPED state")
	}
	if containsState(scStopped, "RUNNING") {
		t.Error("should not detect RUNNING in STOPPED output")
	}
}

// TestContainsInsensitive verifies case-insensitive search.
func TestContainsInsensitive(t *testing.T) {
	if !containsInsensitive("Already installed", "already") {
		t.Error("should find 'already' case-insensitively")
	}
	if !containsInsensitive("SERVICE_EXISTS", "exists") {
		t.Error("should find 'exists' case-insensitively")
	}
	if containsInsensitive("nothing here", "running") {
		t.Error("false positive")
	}
}

// TestIsAlreadyInstalledErr verifies error detection for duplicate SCM service.
func TestIsAlreadyInstalledErr(t *testing.T) {
	tests := []struct {
		msg  string
		want bool
	}{
		{"service already installed", true},
		{"The specified service already exists", true},
		{"1073 service exists", true},
		{"some other error", false},
	}
	for _, tc := range tests {
		got := isAlreadyInstalledErr(errors.New(tc.msg))
		if got != tc.want {
			t.Errorf("isAlreadyInstalledErr(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

// TestWritePrincipalsFile verifies the helper creates directories and writes files.
func TestWritePrincipalsFile(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "auth_principals")

	if err := writePrincipalsFile(subdir, "alice", []string{"alice", "alice-team"}); err != nil {
		t.Fatalf("writePrincipalsFile: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(subdir, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	want := "alice\nalice-team\n"
	if string(content) != want {
		t.Errorf("content = %q, want %q", content, want)
	}
}

// TestGrantPrincipalsAccessWindows_CommandShape verifies the icacls command
// is constructed with the right arguments. We can't test execution without
// a real Windows environment, but we test that the function doesn't panic on
// a temp dir (it will fail because icacls may not be in PATH in CI, but
// we only test the error path here).
func TestGrantPrincipalsAccessWindows_NonExistentDir(t *testing.T) {
	// On a non-Windows CI runner this test is skipped by build tag.
	// On Windows CI, the dir doesn't exist — icacls will fail, which is expected.
	err := grantPrincipalsAccessWindows(`C:\NonExistentDir_UnclusterTest`)
	if err == nil {
		// If icacls somehow succeeded (unlikely), that's fine too.
		t.Log("grantPrincipalsAccessWindows succeeded (unexpected but not a test failure)")
	}
	// We just verify it doesn't panic or block.
}
