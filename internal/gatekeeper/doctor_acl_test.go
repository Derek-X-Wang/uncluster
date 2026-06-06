package gatekeeper

import (
	"strings"
	"testing"
)

// TestPrincipalsDirACLResult covers the pure ACL mapping for the INVERTED
// Windows principals-dir doctor check (#127 role-split). The check name and wire
// shape are unchanged (`principals-dir` → `principals/dir_writable`, the name CI
// asserts `--ok`), but the meaning is inverted: a healthy install is one where
// the low-priv `NT SERVICE\UnclusterAgent` account holds NO write grant on the
// dir. An agent write grant inherits onto the per-user files and makes
// Win32-OpenSSH silently ignore them, so it is now a FAILURE.
//
// Lives in a non-tagged file (no //go:build windows) because the mapper takes
// plain bool/string inputs and references no windows.* types — so the matrix
// build verifies it and the host runs it.
func TestPrincipalsDirACLResult(t *testing.T) {
	const dir = `C:\ProgramData\ssh\auth_principals`

	t.Run("ok_when_agent_has_no_write", func(t *testing.T) {
		got := principalsDirACLResult(dir, principalsDirACLProbe{dirOK: true, agentSIDResolved: true, agentHasWrite: false})
		if got.Name != "principals-dir" {
			t.Errorf("Name = %q, want principals-dir", got.Name)
		}
		if got.Status != CheckOK {
			t.Errorf("Status = %v, want CheckOK (agent has no write)", got.Status)
		}
	})

	t.Run("ok_when_agent_sid_unresolvable", func(t *testing.T) {
		// SID does not resolve → the agent cannot possibly hold a grant → OK.
		got := principalsDirACLResult(dir, principalsDirACLProbe{dirOK: true, agentSIDResolved: false})
		if got.Status != CheckOK {
			t.Errorf("Status with unresolvable SID = %v, want CheckOK", got.Status)
		}
	})

	t.Run("fail_when_agent_holds_write", func(t *testing.T) {
		// The #127 regression: the agent must NEVER be able to write auth_principals.
		got := principalsDirACLResult(dir, principalsDirACLProbe{dirOK: true, agentSIDResolved: true, agentHasWrite: true})
		if got.Status != CheckFail {
			t.Errorf("Status with agent write grant = %v, want CheckFail", got.Status)
		}
		if !strings.Contains(got.Message, "UnclusterAgent") {
			t.Errorf("Message = %q, want it to name the agent account", got.Message)
		}
	})

	t.Run("fail_when_dir_missing", func(t *testing.T) {
		got := principalsDirACLResult(dir, principalsDirACLProbe{dirOK: false})
		if got.Status != CheckFail {
			t.Errorf("Status with missing dir = %v, want CheckFail", got.Status)
		}
	})
}

// TestWriterServiceResult covers the writer-service presence/run-state mapping.
func TestWriterServiceResult(t *testing.T) {
	t.Run("ok_when_installed_and_running", func(t *testing.T) {
		got := writerServiceResult(true, true)
		if got.Name != "writer-service" || got.Status != CheckOK {
			t.Errorf("got %+v, want writer-service CheckOK", got)
		}
	})
	t.Run("fail_when_not_installed", func(t *testing.T) {
		if got := writerServiceResult(false, false); got.Status != CheckFail {
			t.Errorf("Status not-installed = %v, want CheckFail", got.Status)
		}
	})
	t.Run("fail_when_installed_not_running", func(t *testing.T) {
		if got := writerServiceResult(true, false); got.Status != CheckFail {
			t.Errorf("Status installed-not-running = %v, want CheckFail", got.Status)
		}
	})
}

// TestSpoolACLResult covers the spool-dir mapping.
func TestSpoolACLResult(t *testing.T) {
	const dir = `C:\ProgramData\uncluster\spool`
	t.Run("ok_when_agent_can_write", func(t *testing.T) {
		got := spoolACLResult(dir, true, true)
		if got.Name != "spool-dir" || got.Status != CheckOK {
			t.Errorf("got %+v, want spool-dir CheckOK", got)
		}
	})
	t.Run("fail_when_missing", func(t *testing.T) {
		if got := spoolACLResult(dir, false, false); got.Status != CheckFail {
			t.Errorf("Status missing = %v, want CheckFail", got.Status)
		}
	})
	t.Run("fail_when_agent_cannot_write", func(t *testing.T) {
		if got := spoolACLResult(dir, true, false); got.Status != CheckFail {
			t.Errorf("Status no-write = %v, want CheckFail", got.Status)
		}
	})
}

// TestPerUserPrincipalsACLResult covers the per-user-file scan mapping.
func TestPerUserPrincipalsACLResult(t *testing.T) {
	const dir = `C:\ProgramData\ssh\auth_principals`
	t.Run("ok_when_no_unsafe_files", func(t *testing.T) {
		got := perUserPrincipalsACLResult(dir, nil)
		if got.Name != "principals-file-acl" || got.Status != CheckOK {
			t.Errorf("got %+v, want principals-file-acl CheckOK", got)
		}
	})
	t.Run("fail_when_unsafe_file_present", func(t *testing.T) {
		got := perUserPrincipalsACLResult(dir, []string{"derek"})
		if got.Status != CheckFail {
			t.Errorf("Status with unsafe file = %v, want CheckFail", got.Status)
		}
		if !strings.Contains(got.Message, "derek") {
			t.Errorf("Message = %q, want it to name the offending file", got.Message)
		}
	})
}

// TestConfigACLResult covers the pure mapping for the Windows config-ownership
// doctor check (#104). The Unix doctor verifies the system agent.toml is
// readable by the service account (root:<service account> 0640); the Windows
// equivalent is the DACL granting `NT SERVICE\UnclusterAgent` READ. Absent file
// → warn (doctor may run pre-install); SID resolved but no read grant → fail
// (the service cannot read its config and will not start, #77).
func TestConfigACLResult(t *testing.T) {
	const path = `C:\ProgramData\uncluster\agent.toml`

	t.Run("warn_when_absent", func(t *testing.T) {
		got := configACLResult(path, configACLProbe{exists: false})
		if got.Name != "config-ownership" {
			t.Errorf("Name = %q, want config-ownership", got.Name)
		}
		if got.Status != CheckWarn {
			t.Errorf("Status when absent = %v, want CheckWarn (doctor may run pre-install)", got.Status)
		}
	})

	t.Run("ok_when_service_account_granted_read", func(t *testing.T) {
		got := configACLResult(path, configACLProbe{exists: true, sidResolved: true, grantsRead: true})
		if got.Status != CheckOK {
			t.Errorf("Status = %v, want CheckOK (service account can read config)", got.Status)
		}
	})

	t.Run("fail_when_no_read_grant", func(t *testing.T) {
		got := configACLResult(path, configACLProbe{exists: true, sidResolved: true, grantsRead: false})
		if got.Status != CheckFail {
			t.Errorf("Status without read grant = %v, want CheckFail (service cannot read config)", got.Status)
		}
		if !strings.Contains(got.Message, "UnclusterAgent") {
			t.Errorf("Message = %q, want it to name the service account", got.Message)
		}
	})

	t.Run("fail_when_sid_unresolvable", func(t *testing.T) {
		got := configACLResult(path, configACLProbe{exists: true, sidResolved: false})
		if got.Status != CheckFail {
			t.Errorf("Status with unresolvable SID = %v, want CheckFail", got.Status)
		}
	})
}
