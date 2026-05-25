//go:build windows

package ca

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// restrictFileACL applies a Windows DACL to path that allows only:
//   - SYSTEM (full control)
//   - Administrators (full control)
//
// This is the Windows equivalent of chmod 0600 on Unix.
// All other accounts (including the file owner if not in Administrators) are
// implicitly denied access by the protected empty DACL (deny by default).
func restrictFileACL(path string) error {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("ca: CreateWellKnownSid SYSTEM: %w", err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("ca: CreateWellKnownSid Administrators: %w", err)
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
		return fmt.Errorf("ca: ACLFromEntries: %w", err)
	}

	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,  // owner — unchanged
		nil,  // group — unchanged
		acl,
		nil, // sacl — unchanged
	)
	if err != nil {
		return fmt.Errorf("ca: SetNamedSecurityInfo %s: %w", path, err)
	}
	return nil
}

// checkFileACL on Windows verifies that the file's DACL does not grant access
// to accounts other than SYSTEM and Administrators.
// Returns &loosePerm if a broad SID (Everyone, AuthenticatedUsers, or any
// non-SYSTEM/non-Admin SID) appears in an allow ACE.
func checkFileACL(path string) error {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("ca: GetNamedSecurityInfo %s: %w", path, err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("ca: get DACL: %w", err)
	}
	if dacl == nil {
		// NULL DACL = unrestricted access — reject.
		return &loosePerm{path: path}
	}

	// Well-known SIDs to allow.
	systemSID, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	adminSID, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	everyoneSID, _ := windows.CreateWellKnownSid(windows.WinWorldSid)
	authUsersSID, _ := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)

	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(everyoneSID) || sid.Equals(authUsersSID) {
			return &loosePerm{path: path}
		}
		// Allow SYSTEM and Administrators; any other SID = loose.
		if !sid.Equals(systemSID) && !sid.Equals(adminSID) {
			return &loosePerm{path: path}
		}
	}
	return nil
}
