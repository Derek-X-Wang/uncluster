//go:build windows

package gatekeeper

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// checkPrincipalsACLWindows verifies the principals dir exists, is a directory,
// and grants `NT SERVICE\UnclusterAgent` write access — all by READING the
// DACL, never writing. Replaces the old write-probe (create+remove temp file)
// which violated the ADR-0009 `inspect` contract (#104).
func checkPrincipalsACLWindows(dir string) CheckResult {
	fi, err := os.Stat(dir)
	if err != nil {
		return CheckResult{Name: "principals-dir", Status: CheckFail,
			Message: dir + " not found. Run: uncluster agent install"}
	}
	if !fi.IsDir() {
		return CheckResult{Name: "principals-dir", Status: CheckFail,
			Message: dir + " exists but is not a directory"}
	}
	sidResolved, grants := serviceAccountHasAccess(dir, windows.FILE_GENERIC_WRITE)
	return principalsACLResult(dir, sidResolved, grants)
}

// checkConfigACLWindows verifies the system config file exists and grants
// `NT SERVICE\UnclusterAgent` read access (the Windows analog of the Unix
// root:<service account> 0640 readability check). Non-mutating: reads the DACL.
func checkConfigACLWindows(path string) CheckResult {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return configACLResult(path, configACLProbe{exists: false})
		}
		// Stat error other than not-exist: surface as a fail with the path.
		return CheckResult{Name: "config-ownership", Status: CheckFail,
			Message: "stat " + path + ": " + err.Error()}
	}
	sidResolved, grants := serviceAccountHasAccess(path, windows.FILE_GENERIC_READ)
	return configACLResult(path, configACLProbe{exists: true, sidResolved: sidResolved, grantsRead: grants})
}

// serviceAccountHasAccess reads the object's DACL (non-mutating) and reports
// whether `NT SERVICE\UnclusterAgent` is granted the given access mask. Returns
// (sidResolved, granted):
//   - sidResolved=false when the virtual account SID cannot be looked up (the
//     service was never registered with SCM) — granted is then meaningless.
//   - granted=true when an ALLOW ACE on that SID carries every bit in wantMask
//     AND no DENY ACE on that SID strips any of those bits.
//
// The icacls `M` (Modify) grant install applies maps to FILE_GENERIC_WRITE's
// bits; a `(OI)(CI)` inherited grant lands as an explicit ACE on the child dir,
// so enumerating the dir's own DACL suffices. DENY ACEs are honored because
// Windows evaluates DENY before ALLOW.
func serviceAccountHasAccess(path string, wantMask windows.ACCESS_MASK) (sidResolved, granted bool) {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\UnclusterAgent`)
	if err != nil || sid == nil {
		return false, false
	}

	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		// SID resolved but DACL unreadable — cannot confirm the grant; treat as
		// not-granted so doctor fails legibly rather than silently passing.
		return true, false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		// No DACL present means no explicit grant (a null DACL would grant
		// everyone, but install always writes a protected DACL with explicit
		// ACEs — a missing one is a regression).
		return true, false
	}

	var allowBits, denyBits windows.ACCESS_MASK
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			continue
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !aceSID.Equals(sid) {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			allowBits |= ace.Mask
		case windows.ACCESS_DENIED_ACE_TYPE:
			denyBits |= ace.Mask
		}
	}
	// Granted only if every wanted bit is allowed and none is denied.
	effective := allowBits &^ denyBits
	return true, effective&wantMask == wantMask
}
