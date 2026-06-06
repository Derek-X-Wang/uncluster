//go:build windows

package gatekeeper

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// principalsWriteMask is the set of access bits that constitute "can modify the
// file" for the purposes of Win32-OpenSSH's secure-permission check. A per-user
// AuthorizedPrincipalsFile granting ANY of these to a principal other than
// SYSTEM, Administrators, or the agent's service account is rejected by sshd
// ("bad ownership or modes") and silently ignored (#127). GENERIC_ALL and
// GENERIC_WRITE are generic forms that map onto these; we test them explicitly
// because an ACE may carry the generic bit rather than the mapped specific bits.
const principalsWriteMask = windows.FILE_WRITE_DATA |
	windows.FILE_APPEND_DATA |
	windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES |
	windows.WRITE_DAC |
	windows.WRITE_OWNER |
	windows.DELETE |
	windows.GENERIC_WRITE |
	windows.GENERIC_ALL

// checkPerUserPrincipalsFilesWindows scans every per-user file in the principals
// dir and reports a CheckResult flagging any file Win32-OpenSSH would reject —
// i.e. one whose OWNER is not {SYSTEM, Administrators}, or whose DACL grants a
// write-class right to any principal outside {SYSTEM, Administrators}. This
// mirrors Win32-OpenSSH's check_secure_file_permission (verified against
// upstream for #127): a principals file failing either test is silently ignored
// and login is denied. Non-mutating (reads owner + DACL only), honoring the
// ADR-0009 `inspect` contract. Skips `.tmp` files (in-flight atomic writes) and
// subdirectories.
//
// The allow-list here is deliberately {SYSTEM, Administrators} — NOT the agent.
// Win32-OpenSSH does NOT exempt service/virtual accounts, so an agent write ACE
// (or agent owner) would itself get the file rejected. The #127 normalization
// (restrictPrincipalsFileACL) therefore grants the agent nothing on the file
// and sets owner=Administrators; this check enforces that exact shape.
func checkPerUserPrincipalsFilesWindows(dir string) CheckResult {
	unsafeFiles := scanUnsafePrincipalsFiles(dir)
	return perUserPrincipalsACLResult(dir, unsafeFiles)
}

// scanUnsafePrincipalsFiles returns the names of per-user principals files that
// Win32-OpenSSH would reject: bad owner, or a write-class ACE for a principal
// other than SYSTEM / Administrators. A file whose owner or DACL cannot be read
// is conservatively reported as unsafe (we cannot confirm it is safe).
func scanUnsafePrincipalsFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Dir missing/unreadable is surfaced by the separate principals-dir
		// check; here, no files to scan → nothing unsafe.
		return nil
	}

	systemSID, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	adminSID, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)

	isAllowedTrustee := func(sid *windows.SID) bool {
		if systemSID != nil && sid.Equals(systemSID) {
			return true
		}
		if adminSID != nil && sid.Equals(adminSID) {
			return true
		}
		return false
	}

	var bad []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".tmp") {
			continue // in-flight atomic write; not the live file
		}
		path := filepath.Join(dir, name)
		if principalsFileIsUnsafe(path, isAllowedTrustee) {
			bad = append(bad, name)
		}
	}
	return bad
}

// principalsFileIsUnsafe reports whether path would be rejected by
// Win32-OpenSSH: its owner is not allowed, OR its DACL grants a write-class
// right (principalsWriteMask) via an ALLOW ACE to a SID that isAllowed reports
// false for. A NULL DACL (everyone full access) or any read failure (owner or
// DACL) counts as unsafe — we cannot confirm the file is locked down.
func principalsFileIsUnsafe(path string, isAllowed func(*windows.SID) bool) bool {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return true // cannot read security info → cannot confirm safe
	}

	// Owner check: Win32-OpenSSH requires the owner be a permitted principal.
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !isAllowed(owner) {
		return true
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return true
	}
	if dacl == nil {
		return true // NULL DACL grants everyone full access
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue // only ALLOW ACEs grant access; DENY only restricts
		}
		if ace.Mask&principalsWriteMask == 0 {
			continue // no write-class bit → harmless (e.g. a read grant)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !isAllowed(sid) {
			return true // a non-allowed principal can write → sshd will reject
		}
	}
	return false
}

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
