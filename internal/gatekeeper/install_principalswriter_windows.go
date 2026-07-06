//go:build windows

package gatekeeper

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// installPrincipalsWriterService registers the LocalSystem
// UnclusterPrincipalsWriter SCM service (#127). Idempotent: on "already
// installed" it probes for BinaryPathName / ServiceStartName drift via `sc qc`
// and rebuilds (Stop → Uninstall → Install) only if drifted, mirroring the
// agent service's installService path (#50).
func installPrincipalsWriterService(ctx context.Context, serviceExe string) error {
	svc, err := buildPrincipalsWriterService(serviceExe)
	if err != nil {
		return err
	}
	err = svc.Install()
	if err == nil {
		return nil
	}
	if !isAlreadyInstalledErr(err) {
		return err
	}
	out, qcErr := exec.CommandContext(ctx, "sc", "qc", agent.WindowsPrincipalsWriterServiceName).CombinedOutput()
	if qcErr != nil {
		return nil // can't query; preserve idempotent behaviour
	}
	drift := detectServiceUnitDrift(string(out), serviceExe, windowsPrincipalsWriterAccount)
	if drift == "" {
		return nil
	}
	_ = exec.CommandContext(ctx, "net", "stop", agent.WindowsPrincipalsWriterServiceName).Run()
	if err := svc.Uninstall(); err != nil {
		return fmt.Errorf("uninstall drifted writer service (%s): %w", drift, err)
	}
	if err := svc.Install(); err != nil {
		return fmt.Errorf("reinstall writer service after drift (%s): %w", drift, err)
	}
	return nil
}

// startPrincipalsWriterServiceWindows starts (or restarts) the writer service.
func startPrincipalsWriterServiceWindows(ctx context.Context) error {
	_ = exec.CommandContext(ctx, "net", "stop", agent.WindowsPrincipalsWriterServiceName).Run()
	out, err := exec.CommandContext(ctx, "net", "start", agent.WindowsPrincipalsWriterServiceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("net start %s: %w\noutput: %s", agent.WindowsPrincipalsWriterServiceName, err, string(out))
	}
	return nil
}

// UninstallPrincipalsWriterService stops and removes the LocalSystem writer SCM
// service. It is wired into the Windows deprovision path via the agent's
// deprovision-cleanup seam (injected by the CLI, which can import gatekeeper) so
// the writer never outlives the agent (#127 invariant; #146). Best-effort: a
// stop failure (already stopped) is ignored; an uninstall error is returned so
// the caller can log it.
//
// The agent-service drift-rebuild path does NOT call this helper: it uninstalls
// the writer inline as part of its stop→uninstall→reinstall rebuild.
func UninstallPrincipalsWriterService(ctx context.Context, serviceExe string) error {
	_ = exec.CommandContext(ctx, "net", "stop", agent.WindowsPrincipalsWriterServiceName).Run()
	svc, err := buildPrincipalsWriterService(serviceExe)
	if err != nil {
		return err
	}
	if err := svc.Uninstall(); err != nil {
		return fmt.Errorf("uninstall writer service: %w", err)
	}
	return nil
}

// writerRequiredPrivileges is the MINIMUM privilege set the LocalSystem
// UnclusterPrincipalsWriter service needs, set via SERVICE_REQUIRED_PRIVILEGES
// so SCM strips every other privilege a default LocalSystem token would carry
// (#127 acceptance: `sc qprivs UnclusterPrincipalsWriter` shows the stripped
// set). The writer only:
//   - reads a spool file under C:\ProgramData\uncluster\spool,
//   - writes per-user files under C:\ProgramData\ssh\auth_principals (it OWNS
//     them as their LocalSystem creator), and
//   - sets owner=SYSTEM + a PROTECTED DACL on its own files.
//
// None of that needs SeRestore/SeTakeOwnership (setting owner=SYSTEM on a file
// you already own is unprivileged) — those are deliberately NOT granted, since
// SeRestore ≈ machine-owner (the exact escalation the role-split exists to
// avoid). SeChangeNotifyPrivilege ("Bypass traverse checking") is the one
// privilege ordinary file path resolution relies on and is held by Everyone by
// default; listing only it makes SCM drop SeTcb, SeImpersonate,
// SeAssignPrimaryToken, SeDebug, SeBackup, SeRestore, SeTakeOwnership, and the
// rest of the LocalSystem default set.
var writerRequiredPrivileges = []string{
	"SeChangeNotifyPrivilege",
}

// setWriterRequiredPrivileges applies writerRequiredPrivileges to the writer
// service via ChangeServiceConfig2(SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO).
// kardianos/service exposes no field for this, so we open the service handle
// (mgr) and call the Win32 API directly. Idempotent — re-running install
// re-applies the same set.
//
// The info struct is SERVICE_REQUIRED_PRIVILEGES_INFO { LPWSTR
// pmszRequiredPrivileges } where the string is a MULTI_SZ (each privilege
// NUL-terminated, the whole list double-NUL-terminated). An empty list would
// strip ALL privileges; we always pass at least SeChangeNotifyPrivilege.
func setWriterRequiredPrivileges() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(agent.WindowsPrincipalsWriterServiceName)
	if err != nil {
		return fmt.Errorf("open service %s: %w", agent.WindowsPrincipalsWriterServiceName, err)
	}
	defer s.Close()

	multiSZ, err := privilegesToMultiSZ(writerRequiredPrivileges)
	if err != nil {
		return fmt.Errorf("encode required privileges: %w", err)
	}

	info := serviceRequiredPrivilegesInfo{
		requiredPrivileges: &multiSZ[0],
	}
	err = windows.ChangeServiceConfig2(
		s.Handle,
		windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
		(*byte)(unsafe.Pointer(&info)),
	)
	// Keep multiSZ alive until the syscall has consumed the pointer info holds
	// into it (info.requiredPrivileges = &multiSZ[0]); the GC cannot see that
	// indirection through unsafe.Pointer.
	runtime.KeepAlive(multiSZ)
	if err != nil {
		return fmt.Errorf("ChangeServiceConfig2 required-privileges: %w", err)
	}
	return nil
}

// serviceRequiredPrivilegesInfo mirrors the Win32 SERVICE_REQUIRED_PRIVILEGES_INFO
// struct (a single LPWSTR pointing at a MULTI_SZ). x/sys/windows does not define
// it, so we declare it here. The pointer must outlive the ChangeServiceConfig2
// call — it does, because privilegesToMultiSZ returns a slice the caller keeps
// referenced via &multiSZ[0] until the syscall returns.
type serviceRequiredPrivilegesInfo struct {
	requiredPrivileges *uint16
}

// privilegesToMultiSZ encodes a privilege-name list as a UTF-16 MULTI_SZ:
// "Priv1\0Priv2\0\0". Returns at least "\0\0" for an empty input (which SCM
// reads as "strip everything"); callers that must keep one privilege pass a
// non-empty list.
func privilegesToMultiSZ(privs []string) ([]uint16, error) {
	var out []uint16
	for _, p := range privs {
		u, err := windows.UTF16FromString(p)
		if err != nil {
			return nil, fmt.Errorf("utf16 %q: %w", p, err)
		}
		// UTF16FromString already includes a trailing NUL; append the whole run.
		out = append(out, u...)
	}
	// Final extra NUL terminates the MULTI_SZ. If privs was empty we still emit
	// two NULs so the pointer is valid.
	out = append(out, 0)
	if len(out) == 1 {
		out = append(out, 0)
	}
	return out, nil
}

// restrictPrincipalsDirACLWindows sets the principals DIRECTORY to a PROTECTED
// DACL of {SYSTEM: full (inheritable), Administrators: full (inheritable)} with
// NO ace for `NT SERVICE\UnclusterAgent` (#127 role-split). On the pre-#127
// model the dir granted the agent Modify and that ACE inherited onto every
// per-user file, tripping Win32-OpenSSH's rule 2. Now the agent gets nothing on
// this tree; only the LocalSystem writer (running as SYSTEM) writes here.
//
// Inheritance is stripped (PROTECTED) so a re-install over a host carrying the
// old agent grant scrubs it. The (OI)(CI) inheritance means new per-user files
// inherit {SYSTEM, Administrators} — and the writer additionally stamps each
// file with its own PROTECTED DACL on write, so the file ACL is correct
// regardless of what was inherited.
//
// The dir's OWNER is deliberately left as-is (whatever created it under
// ProgramData — Administrators/TrustedInstaller): Win32-OpenSSH checks each
// per-user FILE's owner, not the dir's, and assigning SYSTEM as the dir owner
// would require SeRestore (not held even by the elevated installer's default
// token).
func restrictPrincipalsDirACLWindows(dir string) error {
	return setProtectedSystemAdminsACL(dir, true /* inheritable */)
}

// agentSpoolAccessMask is the access the low-priv agent needs on the spool dir
// (inherited onto the spool files): read (poll applied.json), write (create the
// policy.json.tmp), and DELETE.
//
// DELETE is load-bearing (#175): the agent submits desired-state via an atomic
// tmp→rename (agent.atomicWriteSpoolFile), and on NTFS renaming/replacing a file
// requires DELETE on the source (GENERIC_WRITE maps to FILE_GENERIC_WRITE, which
// does NOT include DELETE). Without it the rename — and even the failed-path
// os.Remove(tmp) cleanup — fail, so policy.json is never produced and NO Policy
// ever reaches the principals files. This regressed silently because the only
// Windows apply CI exercised was deprovision (an empty policy onto an
// already-empty dir), which never needs the write path.
//
// Threat model (ADR-0004): DELETE on the spool grants the agent NO escalation.
// The worst a compromised agent gains is deleting/replacing its OWN spool files
// (policy.json / applied.json) — self-DoS on its own control channel, already
// achievable by simply not applying policy. The mask deliberately omits
// WRITE_DAC/WRITE_OWNER, so the agent cannot weaken the spool ACL; the writer
// re-validates every payload and only ever writes under the hardcoded,
// agent-inaccessible principals dir. The spool's safety is its PROTECTED DACL,
// not the withholding of DELETE.
const agentSpoolAccessMask windows.ACCESS_MASK = windows.GENERIC_READ | windows.GENERIC_WRITE | windows.DELETE

// agentSpoolACE builds the inheritable EXPLICIT_ACCESS the installer grants the
// low-priv agent SID on the spool dir. Extracted so the exact mask (incl.
// DELETE) is unit-testable at the level the #175 bug escaped.
func agentSpoolACE(agentSID *windows.SID) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: agentSpoolAccessMask,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(agentSID),
		},
	}
}

// createSpoolDirWithACL creates the agent↔writer spool dir and applies its ACL:
//   - SYSTEM: full (the writer reads the desired-state and writes applied.json);
//   - Administrators: full (operator inspection);
//   - NT SERVICE\UnclusterAgent: read + write + DELETE (submit desired-state
//     via atomic tmp→rename, read applied.json — see agentSpoolAccessMask for
//     why DELETE is required and why it is safe, #175).
//
// This is the ONE place the agent is granted write — and it is the spool, not
// auth_principals. A compromised agent can at most drop a desired-state here;
// the writer re-validates it and renders files only under the hardcoded
// principals dir, so the spool grant cannot become a principals write (#127).
// PROTECTED so the dir does not inherit broad ProgramData ACEs.
func createSpoolDirWithACL(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create spool dir %s: %w", dir, err)
	}

	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("CreateWellKnownSid SYSTEM: %w", err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("CreateWellKnownSid Administrators: %w", err)
	}

	ea := []windows.EXPLICIT_ACCESS{
		fullControlACE(systemSID, true),
		fullControlACE(adminSID, true),
	}
	// Agent: read + write + DELETE (still not full control — no WRITE_DAC/
	// WRITE_OWNER, so it cannot rewrite the spool's own ACL). See
	// agentSpoolACE / agentSpoolAccessMask for why DELETE is load-bearing and
	// why it grants no escalation (#175).
	if agentSID, _, _, lerr := windows.LookupSID("", windowsServiceAccountName); lerr == nil && agentSID != nil {
		ea = append(ea, agentSpoolACE(agentSID))
	}

	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		return fmt.Errorf("ACLFromEntries (spool): %w", err)
	}
	// Owner left as-is (the creating Administrator). Setting it to SYSTEM would
	// need SeRestore; the spool's safety is its PROTECTED DACL, not its owner.
	if err := windows.SetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return fmt.Errorf("SetNamedSecurityInfo (spool) %s: %w", dir, err)
	}
	return nil
}

// setProtectedSystemAdminsACL applies a PROTECTED DACL of {SYSTEM: full,
// Administrators: full} to path (owner left unchanged). If inheritable, the ACEs
// use (OI)(CI) so children inherit them; otherwise NO_INHERITANCE. Used for the
// principals dir (inheritable) and reusable for any tree that must be locked to
// SYSTEM/Admins with no agent access.
//
// Owner is NOT set: assigning SYSTEM as owner needs SeRestore (not in the
// elevated installer's default token), and the security property here is the
// PROTECTED DACL — the dir's existing ProgramData owner (Administrators /
// TrustedInstaller) is already acceptable.
func setProtectedSystemAdminsACL(path string, inheritable bool) error {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("CreateWellKnownSid SYSTEM: %w", err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("CreateWellKnownSid Administrators: %w", err)
	}
	ea := []windows.EXPLICIT_ACCESS{
		fullControlACE(systemSID, inheritable),
		fullControlACE(adminSID, inheritable),
	}
	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		return fmt.Errorf("ACLFromEntries: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return fmt.Errorf("SetNamedSecurityInfo %s: %w", path, err)
	}
	return nil
}

// fullControlACE builds a GENERIC_ALL EXPLICIT_ACCESS for sid. inheritable picks
// (OI)(CI) container+object inheritance for a directory, else NO_INHERITANCE.
func fullControlACE(sid *windows.SID, inheritable bool) windows.EXPLICIT_ACCESS {
	var inh uint32 = windows.NO_INHERITANCE
	if inheritable {
		inh = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       inh,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
