package gatekeeper

import (
	"strings"
	"testing"
)

// TestPrincipalsACLResult covers the pure ACL-grant mapping for the Windows
// principals-dir doctor check (#104). The Windows install grants the
// `NT SERVICE\UnclusterAgent` virtual account write access via icacls; CI
// asserted that grant by grepping `icacls` output for "UnclusterAgent"
// (`assert-principals-acl`). doctor now reads the DACL directly (non-mutating,
// per the ADR-0009 inspect contract — replacing the old write-probe that
// created+removed a temp file) and grades the grant. The Win32 DACL read +
// ACE enumeration is integration-only; this exercises the OK/Fail mapping
// deterministically so the contract is testable on every platform.
//
// Lives in a non-tagged file (no //go:build windows) because the mapper takes
// plain bool/string inputs and references no windows.* types — so the matrix
// build verifies it and the host runs it.
func TestPrincipalsACLResult(t *testing.T) {
	const dir = `C:\ProgramData\ssh\auth_principals`

	t.Run("ok_when_service_account_granted_write", func(t *testing.T) {
		got := principalsACLResult(dir, true, true)
		if got.Name != "principals-dir" {
			t.Errorf("Name = %q, want principals-dir", got.Name)
		}
		if got.Status != CheckOK {
			t.Errorf("Status = %v, want CheckOK (service account has write)", got.Status)
		}
	})

	t.Run("fail_when_service_account_not_granted", func(t *testing.T) {
		// SID resolved, but no write-granting ACE — the #83-class regression
		// where install ran before the virtual account existed.
		got := principalsACLResult(dir, true, false)
		if got.Status != CheckFail {
			t.Errorf("Status without write grant = %v, want CheckFail", got.Status)
		}
		if !strings.Contains(got.Message, "UnclusterAgent") {
			t.Errorf("Message = %q, want it to name the service account", got.Message)
		}
	})

	t.Run("fail_when_sid_unresolvable", func(t *testing.T) {
		// SID cannot be resolved → the service was never registered with SCM,
		// so the grant cannot exist. Fail (matches CI's hard assert).
		got := principalsACLResult(dir, false, false)
		if got.Status != CheckFail {
			t.Errorf("Status with unresolvable SID = %v, want CheckFail", got.Status)
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

// TestPerUserPrincipalsACLResult covers the pure mapping for the new per-user
// AuthorizedPrincipalsFile safety check (#127). Win32-OpenSSH silently ignores
// a principals file writable by a non-admin/non-SYSTEM principal, so a file
// inheriting the dir's `NT SERVICE\UnclusterAgent` Modify ACE breaks login
// while doctor (pre-#127, dir-grant-only) reported healthy. The mapper grades
// the scan result: no offenders → OK; any offender → Fail naming the file(s).
//
// Lives in the non-tagged test file (no //go:build windows) because the mapper
// takes plain []string/string and references no windows.* types — the matrix
// build verifies it and the host runs it.
func TestPerUserPrincipalsACLResult(t *testing.T) {
	const dir = `C:\ProgramData\ssh\auth_principals`

	t.Run("ok_when_no_unsafe_files", func(t *testing.T) {
		got := perUserPrincipalsACLResult(dir, nil)
		if got.Name != "principals-file-acl" {
			t.Errorf("Name = %q, want principals-file-acl", got.Name)
		}
		if got.Status != CheckOK {
			t.Errorf("Status with no unsafe files = %v, want CheckOK", got.Status)
		}
	})

	t.Run("ok_when_empty_slice", func(t *testing.T) {
		got := perUserPrincipalsACLResult(dir, []string{})
		if got.Status != CheckOK {
			t.Errorf("Status with empty slice = %v, want CheckOK", got.Status)
		}
	})

	t.Run("fail_names_single_offender", func(t *testing.T) {
		got := perUserPrincipalsACLResult(dir, []string{"derek"})
		if got.Status != CheckFail {
			t.Errorf("Status with one unsafe file = %v, want CheckFail", got.Status)
		}
		if !strings.Contains(got.Message, "derek") {
			t.Errorf("Message = %q, want it to name the offending file", got.Message)
		}
		// The fail message must point the operator at the silent-ignore failure mode.
		if !strings.Contains(got.Message, "silently ignore") {
			t.Errorf("Message = %q, want it to explain the sshd silent-ignore behaviour", got.Message)
		}
	})

	t.Run("fail_names_all_offenders", func(t *testing.T) {
		got := perUserPrincipalsACLResult(dir, []string{"derek", "alice"})
		if got.Status != CheckFail {
			t.Errorf("Status = %v, want CheckFail", got.Status)
		}
		if !strings.Contains(got.Message, "derek") || !strings.Contains(got.Message, "alice") {
			t.Errorf("Message = %q, want it to name every offending file", got.Message)
		}
	})
}
