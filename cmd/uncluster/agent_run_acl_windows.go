//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// errorLogAgentAccess is the access the agent service account is granted on the
// SCM error log: read + write/append, so it can keep appending diagnostics. The
// agent already owns the file it creates, but the explicit ACE keeps it
// writable even if ownership changes, and read lets `agent doctor`-style tooling
// inspect it from the service identity.
const errorLogAgentAccess = windows.GENERIC_READ | windows.GENERIC_WRITE

// restrictErrorLogACL applies a PROTECTED DACL to the SCM error log:
//   - SYSTEM: full control;
//   - Administrators: full control (so the operator can READ the diagnostics);
//   - NT SERVICE\UnclusterAgent: read + write (the agent appends to it).
//
// Inheritance is stripped (PROTECTED_DACL_SECURITY_INFORMATION) so the log does
// not pick up whatever broad ACEs C:\ProgramData\uncluster carries. Unlike the
// principals file (#127), this log is NOT read by sshd, so it has no
// Win32-OpenSSH owner/mode constraint — the only requirement (issue #128) is
// "SYSTEM write, Administrators read", which this satisfies and tightens.
//
// Mirrors the restrictFileACL / restrictConfigACL protected-DACL family. If the
// agent virtual-account SID is unresolvable, that ACE is skipped — the agent is
// the file's creator/owner and can still append regardless.
func restrictErrorLogACL(path string) error {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("CreateWellKnownSid SYSTEM: %w", err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("CreateWellKnownSid Administrators: %w", err)
	}

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

	if agentSID := lookupAgentServiceSID(); agentSID != nil {
		ea = append(ea, windows.EXPLICIT_ACCESS{
			AccessPermissions: errorLogAgentAccess,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(agentSID),
			},
		})
	}

	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		return fmt.Errorf("ACLFromEntries (error log): %w", err)
	}

	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	)
	if err != nil {
		return fmt.Errorf("SetNamedSecurityInfo (error log) %s: %w", path, err)
	}
	return nil
}

// lookupAgentServiceSID resolves the agent's virtual-account SID, or nil if it
// is not yet registered with SCM.
func lookupAgentServiceSID() *windows.SID {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+agent.WindowsServiceName)
	if err != nil {
		return nil
	}
	return sid
}
