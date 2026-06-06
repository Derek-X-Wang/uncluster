//go:build windows

package agent

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// restrictPrincipalsFileACL normalizes a per-user AuthorizedPrincipalsFile so
// Win32-OpenSSH (sshd, running as SYSTEM) will HONOR it instead of silently
// ignoring it.
//
// Win32-OpenSSH's secure-permission check (contrib/win32/win32compat/
// w32-sshfileperm.c, check_secure_file_permission) — verified against the
// upstream source for #127 — enforces TWO things on the principals file:
//
//  1. OWNER must be one of: Administrators, SYSTEM, the connecting user, or
//     TrustedInstaller. Any other owner → "bad ownership or modes", file
//     ignored, login denied.
//  2. No principal OTHER than {Administrators, SYSTEM, connecting user,
//     TrustedInstaller} may hold a write-class right
//     (FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES|FILE_WRITE_EA|FILE_APPEND_DATA|
//     WRITE_DAC|WRITE_OWNER|DELETE). A write ACE for ANY other SID → rejected.
//
// This function is called ONLY by the LocalSystem UnclusterPrincipalsWriter
// service (ADR-0004 Windows amendment / #127 role-split), never by the low-priv
// agent. Because the writer runs as LocalSystem, the tmp file it creates is
// ALREADY owned by SYSTEM — a permitted owner under rule 1 — with NO action on
// our part. We therefore do NOT set the owner here: we only set the PROTECTED
// DACL = {SYSTEM: full, Administrators: full}, inheritance stripped so the
// principals-dir's ACEs (which on the new model grant the agent NOTHING, but
// historically might) cannot survive onto the file.
//
// Why no OWNER_SECURITY_INFORMATION: SETTING a file's owner to a SID other than
// the caller's own token (or one in its token's groups) requires SeRestore /
// SeTakeOwnership — which we deliberately never grant any Uncluster service
// (≈ machine-owner). The LocalSystem writer is SYSTEM, so the file it creates is
// already SYSTEM-owned; setting it again is both redundant and, when the test
// harness runs as an ordinary user, an OUTRIGHT FAILURE ("This security ID may
// not be assigned as the owner of this object"). Relying on natural ownership —
// the exact mechanism the role-split was designed around — keeps this privilege-
// free and lets the render path run under any owner the test harness has.
//
// We never add a write ACE for `NT SERVICE\UnclusterAgent` — that would itself
// trip rule (2) and get the file rejected.
//
// The caller (atomicWritePrincipals) invokes this on the tmp file BEFORE the
// rename. A same-volume rename preserves the security descriptor, so sshd never
// observes a half-written or wrong-ACL live file.
func restrictPrincipalsFileACL(path string) error {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("agent: CreateWellKnownSid SYSTEM: %w", err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("agent: CreateWellKnownSid Administrators: %w", err)
	}

	// DACL: SYSTEM full + Administrators full. No other ACE — in particular no
	// `NT SERVICE\UnclusterAgent` write ACE, which would itself trip
	// Win32-OpenSSH's rule (2) and get the file rejected.
	ea := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(systemSID),
			},
		},
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(adminSID),
			},
		},
	}

	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		return fmt.Errorf("agent: ACLFromEntries (principals file): %w", err)
	}

	// Set ONLY the PROTECTED DACL — no owner change (see the doc comment).
	// PROTECTED_DACL_SECURITY_INFORMATION blocks inheritance so no inherited
	// (writable-by-non-admin) ACE from the principals dir survives on the file.
	// The owner stays whatever created the file: SYSTEM in production (the
	// LocalSystem writer), which Win32-OpenSSH accepts under rule (1).
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, // owner unchanged (already SYSTEM in production)
		nil, // group unchanged
		acl,
		nil, // sacl unchanged
	)
	if err != nil {
		return fmt.Errorf("agent: SetNamedSecurityInfo (principals file) %s: %w", path, err)
	}
	return nil
}
