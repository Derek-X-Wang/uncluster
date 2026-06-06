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
// This is the load-bearing correction to the naive "grant the agent write on
// the file" idea: a `NT SERVICE\UnclusterAgent` write ACE would itself trip
// rule (2) and make sshd reject the file. So the normalized ACL grants the
// agent NOTHING on the file. The agent still rewrites the file via the
// directory-level tmp→rename it already performs (it holds Modify on the
// principals DIR from install — delete-child + add-file — which is sufficient
// to replace the file without any file-level ACE). A same-volume rename
// preserves the tmp file's security descriptor, so the DACL/owner set here
// survives onto the live file.
//
// The applied normalization is therefore:
//   - OWNER set to Administrators (a permitted owner under rule 1);
//   - DACL = PROTECTED {SYSTEM: full, Administrators: full} — inheritance
//     stripped so the dir's inherited UnclusterAgent Modify ACE does not
//     survive, SYSTEM-readable for sshd, and NO write ACE for any principal
//     outside {SYSTEM, Administrators} (rule 2 satisfied).
//
// NOTE (#127, surfaced for review): setting the owner to Administrators from
// the low-privilege `NT SERVICE\UnclusterAgent` virtual account requires
// SeRestorePrivilege / SeTakeOwnershipPrivilege, which that account does not
// hold by default. On a host where the owner-set is not permitted this returns
// an error (a VISIBLE failed policy apply, never a silent wrong-owner file).
// The durable resolution — run the agent service as LocalSystem so files it
// creates are already SYSTEM-owned, or grant the scoped privilege — is a
// service-identity decision tracked in the PR discussion, to be confirmed on
// the #16 real-hardware session.
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

	// Set OWNER=Administrators and the PROTECTED DACL in one call.
	// PROTECTED_DACL_SECURITY_INFORMATION blocks inheritance so no inherited
	// (writable-by-non-admin) ACE from the principals dir survives on the file.
	// OWNER_SECURITY_INFORMATION fixes the owner to a principal Win32-OpenSSH
	// accepts (rule 1).
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION|
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		adminSID, // owner → Administrators
		nil,      // group unchanged
		acl,
		nil, // sacl unchanged
	)
	if err != nil {
		return fmt.Errorf("agent: SetNamedSecurityInfo (principals file) %s: %w", path, err)
	}
	return nil
}
