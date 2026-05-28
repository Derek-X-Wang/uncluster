//go:build windows

package agent

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// restrictConfigACL applies a DACL to agent.toml restricting access to:
//   - SYSTEM (full control)
//   - Administrators (full control)
//
// This is the Windows equivalent of mode 0600 on Unix for the per-user
// config path. The system-wide path uses restrictSystemConfigACL which
// also grants the service virtual account read access.
func restrictConfigACL(path string) error {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("agent: CreateWellKnownSid SYSTEM: %w", err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("agent: CreateWellKnownSid Administrators: %w", err)
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

	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		return fmt.Errorf("agent: ACLFromEntries: %w", err)
	}

	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	)
	if err != nil {
		return fmt.Errorf("agent: SetNamedSecurityInfo %s: %w", path, err)
	}
	return nil
}

// restrictSystemConfigACL applies a DACL like restrictConfigACL but also
// grants `NT SERVICE\UnclusterAgent` READ access so the SCM service can
// read its config at startup. If the virtual account does not yet exist
// (SCM creates it lazily on service registration), the service-account ACE
// is silently skipped; install re-runs SaveConfigSystem after the service
// is registered so the grant lands then.
func restrictSystemConfigACL(path string) error {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("agent: CreateWellKnownSid SYSTEM: %w", err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("agent: CreateWellKnownSid Administrators: %w", err)
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

	if svcSID := lookupServiceSID(); svcSID != nil {
		ea = append(ea, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_READ,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(svcSID),
			},
		})
	}

	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		return fmt.Errorf("agent: ACLFromEntries (system): %w", err)
	}

	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	)
	if err != nil {
		return fmt.Errorf("agent: SetNamedSecurityInfo (system) %s: %w", path, err)
	}
	return nil
}

// lookupServiceSID returns the SID for `NT SERVICE\UnclusterAgent` or nil
// if the SID is not yet resolvable (service has not been registered with
// SCM).
func lookupServiceSID() *windows.SID {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\UnclusterAgent`)
	if err != nil {
		return nil
	}
	return sid
}
