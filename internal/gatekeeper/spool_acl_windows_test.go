//go:build windows

package gatekeeper

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// currentUserSID returns the test process's user SID (always resolvable, so the
// round-trip test does not depend on the real NT SERVICE\UnclusterAgent account
// existing).
func currentUserSID(t *testing.T) *windows.SID {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	return u.User.Sid
}

// applyProtectedDACL sets a PROTECTED DACL of the given entries on path (mirrors
// what createSpoolDirWithACL does to the spool dir).
func applyProtectedDACL(t *testing.T, path string, ea []windows.EXPLICIT_ACCESS) {
	t.Helper()
	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		t.Fatalf("ACLFromEntries: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	); err != nil {
		t.Fatalf("SetNamedSecurityInfo: %v", err)
	}
}

// TestAgentSpoolAccessMask guards the #175 fix at the mask level: the agent's
// spool ACE must carry DELETE (for the atomic tmp→rename) plus RW, and must NOT
// carry ACL-rewrite/owner rights (ADR-0004 — a compromised agent must not be
// able to weaken the spool's own protection).
func TestAgentSpoolAccessMask(t *testing.T) {
	if agentSpoolAccessMask&windows.DELETE == 0 {
		t.Errorf("agentSpoolAccessMask (%#x) missing DELETE — atomic tmp→rename cannot complete (#175)", agentSpoolAccessMask)
	}
	if agentSpoolAccessMask&windows.GENERIC_WRITE == 0 {
		t.Errorf("agentSpoolAccessMask (%#x) missing GENERIC_WRITE — agent cannot create policy.json.tmp", agentSpoolAccessMask)
	}
	if agentSpoolAccessMask&windows.GENERIC_READ == 0 {
		t.Errorf("agentSpoolAccessMask (%#x) missing GENERIC_READ — agent cannot poll applied.json", agentSpoolAccessMask)
	}
	if agentSpoolAccessMask&(windows.WRITE_DAC|windows.WRITE_OWNER) != 0 {
		t.Errorf("agentSpoolAccessMask (%#x) grants WRITE_DAC/WRITE_OWNER — agent must not be able to rewrite the spool ACL (ADR-0004)", agentSpoolAccessMask)
	}
}

// TestSpoolACLRenameCapabilityRoundTrip applies the REAL installer ACE to an
// object and verifies — through the SAME DACL read the doctor uses
// (sidHasAccess) — that the #175 fix grants write+rename AND that the pre-#175
// (plain-write) grant is correctly reported as INSUFFICIENT. This is exactly the
// level the outage escaped: the old doctor asked only for FILE_GENERIC_WRITE and
// stayed green while every policy apply silently failed.
//
// The ACE is applied to a temp FILE inside t.TempDir() (not a dir we must
// delete): even a restrictive PROTECTED DACL on the file does not impede
// cleanup, because RemoveAll deletes it via FILE_DELETE_CHILD on the
// (normally-ACL'd) parent temp dir.
func TestSpoolACLRenameCapabilityRoundTrip(t *testing.T) {
	sid := currentUserSID(t)
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid SYSTEM: %v", err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid Administrators: %v", err)
	}

	newObj := func(t *testing.T) string {
		t.Helper()
		f, err := os.CreateTemp(t.TempDir(), "spoolacl-*")
		if err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
		name := f.Name()
		_ = f.Close()
		return name
	}

	t.Run("fixed_ace_grants_write_and_rename", func(t *testing.T) {
		p := newObj(t)
		applyProtectedDACL(t, p, []windows.EXPLICIT_ACCESS{
			fullControlACE(systemSID, true),
			fullControlACE(adminSID, true),
			agentSpoolACE(sid),
		})
		if !sidHasAccess(p, sid, spoolApplyMask) {
			t.Errorf("fixed spool ACE does not grant FILE_GENERIC_WRITE|DELETE — the #175 fix is ineffective")
		}
	})

	t.Run("legacy_write_only_ace_reported_insufficient", func(t *testing.T) {
		p := newObj(t)
		legacy := agentSpoolACE(sid)
		legacy.AccessPermissions = windows.GENERIC_READ | windows.GENERIC_WRITE // pre-#175: no DELETE
		applyProtectedDACL(t, p, []windows.EXPLICIT_ACCESS{
			fullControlACE(systemSID, true),
			fullControlACE(adminSID, true),
			legacy,
		})
		// It DID grant plain write — which is why the pre-#175 doctor check
		// (wantMask = FILE_GENERIC_WRITE) stayed green throughout the outage.
		if !sidHasAccess(p, sid, windows.FILE_GENERIC_WRITE) {
			t.Errorf("legacy write-only ACE unexpectedly lacks plain write")
		}
		// ...but the strengthened check MUST report it as lacking rename
		// capability, so the silent policy-apply failure surfaces in doctor.
		if sidHasAccess(p, sid, spoolApplyMask) {
			t.Errorf("legacy write-only ACE wrongly reported as rename-capable — doctor would miss #175")
		}
	})
}
