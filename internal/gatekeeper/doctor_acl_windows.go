//go:build windows

package gatekeeper

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// scQuery runs `sc.exe query <name>` (read-only, ADR-0009 inspect-safe) and
// returns its combined output. An error means the service is not installed.
func scQuery(name string) (string, error) {
	out, err := exec.Command("sc.exe", "query", name).CombinedOutput()
	return string(out), err
}

// principalsWriteMask is the set of access bits that constitute "can modify the
// file/dir" for the purposes of Win32-OpenSSH's secure-permission check. A
// principal OTHER than {SYSTEM, Administrators} holding ANY of these on an
// AuthorizedPrincipalsFile gets the file rejected ("bad ownership or modes",
// silently ignored, login denied — #127). The same mask defines "the agent has
// a write grant" for the inverted principals-dir check.
const principalsWriteMask = windows.FILE_WRITE_DATA |
	windows.FILE_APPEND_DATA |
	windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES |
	windows.WRITE_DAC |
	windows.WRITE_OWNER |
	windows.DELETE |
	windows.GENERIC_WRITE |
	windows.GENERIC_ALL

// checkPrincipalsACLWindows verifies the principals dir is locked down for the
// #127 role-split: it exists, is a directory, and the low-priv
// `NT SERVICE\UnclusterAgent` account holds NO write grant on it. The check is
// INVERTED from the pre-#127 version (which required the agent to HAVE write):
// an agent write grant inherits onto the per-user files and makes Win32-OpenSSH
// silently ignore them, so it is now a FAILURE. All by READING the DACL, never
// writing (ADR-0009 `inspect` contract).
func checkPrincipalsACLWindows(dir string) CheckResult {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return principalsDirACLResult(dir, principalsDirACLProbe{dirOK: false})
	}
	sidResolved, hasWrite := serviceAccountHasAnyWriteBit(dir)
	return principalsDirACLResult(dir, principalsDirACLProbe{
		dirOK:            true,
		agentSIDResolved: sidResolved,
		agentHasWrite:    hasWrite,
	})
}

// serviceAccountHasAnyWriteBit is like serviceAccountHasAccess but reports
// whether the agent holds ANY bit in principalsWriteMask (not all). Used by the
// inverted principals-dir check: a single write-class ACE is enough to break
// sshd, so we must flag it. serviceAccountHasAccess requires the FULL mask,
// which is the wrong test for "does the agent have any write at all".
func serviceAccountHasAnyWriteBit(path string) (sidResolved, anyWrite bool) {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\UnclusterAgent`)
	if err != nil || sid == nil {
		return false, false
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return true, false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
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
	effective := allowBits &^ denyBits
	return true, effective&principalsWriteMask != 0
}

// checkPerUserPrincipalsFilesWindows scans every per-user file in the principals
// dir and reports a CheckResult flagging any file Win32-OpenSSH would reject —
// one whose OWNER is not {SYSTEM, Administrators}, or whose DACL grants a
// write-class right to any principal outside {SYSTEM, Administrators}. This
// mirrors Win32-OpenSSH's check_secure_file_permission (verified against
// upstream for #127): such a file is silently ignored and login is denied.
// Non-mutating (reads owner + DACL only), honoring the ADR-0009 `inspect`
// contract. Skips `.tmp` files (in-flight atomic writes) and subdirectories.
//
// The allow-list is deliberately {SYSTEM, Administrators} — NOT the agent, and
// NOT the writer's LocalSystem (which IS SYSTEM). Win32-OpenSSH does not exempt
// service/virtual accounts, so an agent write ACE would itself get the file
// rejected. The writer renders files owned by SYSTEM with a PROTECTED
// {SYSTEM, Administrators} DACL; this check enforces exactly that shape.
func checkPerUserPrincipalsFilesWindows(dir string) CheckResult {
	unsafeFiles := scanUnsafePrincipalsFiles(dir)
	return perUserPrincipalsACLResult(dir, unsafeFiles)
}

// scanUnsafePrincipalsFiles returns the names of per-user principals files that
// Win32-OpenSSH would reject. A file whose owner or DACL cannot be read is
// conservatively reported as unsafe (we cannot confirm it is safe).
func scanUnsafePrincipalsFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
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
// false for. A NULL DACL (everyone full access) or any read failure counts as
// unsafe — we cannot confirm the file is locked down.
func principalsFileIsUnsafe(path string, isAllowed func(*windows.SID) bool) bool {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return true
	}
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
			continue
		}
		if ace.Mask&principalsWriteMask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !isAllowed(sid) {
			return true
		}
	}
	return false
}

// checkWriterServiceWindows reports whether the LocalSystem
// UnclusterPrincipalsWriter SCM service is installed and running. Non-mutating:
// a read-only `sc query`. The writer is the only identity that writes principals
// files on Windows, so its absence breaks policy apply (#127).
func checkWriterServiceWindows() CheckResult {
	out, err := scQuery(agent.WindowsPrincipalsWriterServiceName)
	if err != nil {
		return writerServiceResult(false, false)
	}
	return writerServiceResult(true, containsState(out, "RUNNING"))
}

// checkSpoolACLWindows reports whether the agent↔writer spool dir exists and the
// agent account can write it (so it can submit desired-state). Non-mutating:
// stat + DACL read (#127).
func checkSpoolACLWindows(dir string) CheckResult {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return spoolACLResult(dir, false, false)
	}
	sidResolved, grants := serviceAccountHasAccess(dir, windows.FILE_GENERIC_WRITE)
	// If the SID does not resolve, the agent service is not registered — treat
	// as "cannot write" (fail) so doctor surfaces the broken install.
	return spoolACLResult(dir, true, sidResolved && grants)
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
