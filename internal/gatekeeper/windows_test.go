//go:build windows

package gatekeeper

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/agent"
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

// TestPrincipalsWriterServiceAccount verifies the writer runs as LocalSystem
// (#127): Win32-OpenSSH accepts a SYSTEM-owned principals file, so a
// LocalSystem-created file needs no SeRestore — the whole reason the writer is
// LocalSystem and not the low-priv agent.
func TestPrincipalsWriterServiceAccount(t *testing.T) {
	if windowsPrincipalsWriterAccount != "LocalSystem" {
		t.Errorf("writer account = %q, want LocalSystem", windowsPrincipalsWriterAccount)
	}
	if agent.WindowsPrincipalsWriterServiceName != "UnclusterPrincipalsWriter" {
		t.Errorf("writer service name = %q, want UnclusterPrincipalsWriter",
			agent.WindowsPrincipalsWriterServiceName)
	}
}

// TestWriterRequiredPrivilegesMinimal asserts the writer's required-privilege
// set is the documented minimum and — crucially — never includes SeRestore or
// SeTakeOwnership (#127: those are ≈ machine-owner, the exact escalation the
// role-split exists to avoid). The expected `sc qprivs UnclusterPrincipalsWriter`
// output after install is therefore just SeChangeNotifyPrivilege.
func TestWriterRequiredPrivilegesMinimal(t *testing.T) {
	if len(writerRequiredPrivileges) != 1 || writerRequiredPrivileges[0] != "SeChangeNotifyPrivilege" {
		t.Fatalf("writerRequiredPrivileges = %v, want [SeChangeNotifyPrivilege]", writerRequiredPrivileges)
	}
	for _, p := range writerRequiredPrivileges {
		switch p {
		case "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeBackupPrivilege",
			"SeDebugPrivilege", "SeTcbPrivilege", "SeImpersonatePrivilege":
			t.Errorf("writer must NOT request escalation privilege %q (#127)", p)
		}
	}
}

// TestPrivilegesToMultiSZ verifies the MULTI_SZ encoding: each privilege is
// NUL-terminated and the list is double-NUL-terminated, the shape
// SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO expects.
func TestPrivilegesToMultiSZ(t *testing.T) {
	got, err := privilegesToMultiSZ([]string{"SeChangeNotifyPrivilege"})
	if err != nil {
		t.Fatalf("privilegesToMultiSZ: %v", err)
	}
	// "SeChangeNotifyPrivilege" is 23 chars → 23 + NUL (from UTF16FromString) +
	// the trailing terminator NUL = 25 uint16s.
	if n := len(got); n != 25 {
		t.Errorf("multi-SZ len = %d, want 25", n)
	}
	if got[len(got)-1] != 0 || got[len(got)-2] != 0 {
		t.Errorf("multi-SZ not double-NUL terminated: tail = %v", got[len(got)-2:])
	}
}
