package gatekeeper

import (
	"fmt"
	"strings"
)

// perUserPrincipalsACLResult maps the result of scanning the per-user
// AuthorizedPrincipalsFiles to a CheckResult. `unsafe` lists the names of
// per-user files that carry a WRITABLE ACE for some principal other than
// {SYSTEM, Administrators}, or whose owner is not in that set — the exact thing
// Win32-OpenSSH rejects ("bad ownership or modes"), silently ignoring the file
// so cert login is denied even with the right principal present (#127).
//
// Empty `unsafe` → OK. Non-empty → Fail naming the offending file(s). Pure (no
// windows.* types) so the OK/Fail mapping is unit-testable on every platform;
// the DACL read + ACE classification lives in the windows-tagged probe.
func perUserPrincipalsACLResult(dir string, unsafe []string) CheckResult {
	if len(unsafe) == 0 {
		return CheckResult{Name: "principals-file-acl", Status: CheckOK,
			Message: fmt.Sprintf("per-user principals files under %s are owned and writable only by SYSTEM/Administrators", dir)}
	}
	return CheckResult{Name: "principals-file-acl", Status: CheckFail,
		Message: fmt.Sprintf("per-user principals file(s) [%s] have an unsafe owner or a writable ACE for a non-admin/non-SYSTEM principal — Win32-OpenSSH will silently ignore them (login denied). Re-apply policy to normalize. (#127)",
			strings.Join(unsafe, ", "))}
}

// principalsDirACLProbe is the resolved Windows principals-dir ACL state for the
// #127 role-split doctor check. agentSIDResolved is false when
// `NT SERVICE\UnclusterAgent` cannot be looked up (service never registered);
// agentHasWrite is whether the agent account holds a write-class grant on the
// dir. dirOK captures that the dir exists and is a directory (the windows probe
// sets it false on stat failure so the mapping can fail legibly).
type principalsDirACLProbe struct {
	dirOK            bool
	agentSIDResolved bool
	agentHasWrite    bool
}

// principalsDirACLResult maps a resolved Windows principals-dir ACL probe to a
// CheckResult. The check name stays `principals-dir` (→ wire `principals/dir_writable`),
// but its meaning is INVERTED for the #127 role-split: a healthy install is one
// where the low-priv `NT SERVICE\UnclusterAgent` account holds NO write grant on
// the principals dir (the LocalSystem UnclusterPrincipalsWriter is the only
// writer). An agent write grant is the exact thing that makes Win32-OpenSSH
// silently ignore the per-user files, so doctor must FAIL if it is present.
//
// doctor reads the DACL to determine this WITHOUT mutating the directory
// (ADR-0009 `inspect` contract).
//
// Outcomes:
//   - dir missing / not a directory → Fail (install not run).
//   - agent SID resolves AND holds a write grant → Fail (the regression #127
//     guards against — the agent must never be able to write auth_principals).
//   - otherwise (agent has no write, or its SID does not even exist) → OK.
//
// Pure (no windows.* types) so the OK/Fail mapping is unit-testable on every
// platform; the DACL read + ACE enumeration lives in the windows-tagged probe.
func principalsDirACLResult(dir string, p principalsDirACLProbe) CheckResult {
	if !p.dirOK {
		return CheckResult{Name: "principals-dir", Status: CheckFail,
			Message: fmt.Sprintf("%s not found or not a directory. Run: uncluster agent install", dir)}
	}
	if p.agentSIDResolved && p.agentHasWrite {
		return CheckResult{Name: "principals-dir", Status: CheckFail,
			Message: fmt.Sprintf("%s: NT SERVICE\\UnclusterAgent holds a WRITE grant on the principals dir — Win32-OpenSSH would silently ignore the per-user files (login denied). The LocalSystem UnclusterPrincipalsWriter must be the only writer. Run `uncluster agent install` to remove the agent grant. (#127)", dir)}
	}
	return CheckResult{Name: "principals-dir", Status: CheckOK,
		Message: fmt.Sprintf("principals dir ok at %s (no NT SERVICE\\UnclusterAgent write grant; only SYSTEM/Administrators/the LocalSystem writer can write)", dir)}
}

// writerServiceResult maps the resolved presence/run-state of the LocalSystem
// UnclusterPrincipalsWriter service to a CheckResult (#127). The writer is the
// only identity that writes principals files on Windows, so a missing or
// stopped writer means policy apply will time out as a failed apply. Pure so the
// mapping is testable on every platform; the `sc query` lives in the wiring.
func writerServiceResult(installed, running bool) CheckResult {
	if !installed {
		return CheckResult{Name: "writer-service", Status: CheckFail,
			Message: "UnclusterPrincipalsWriter service not installed — principals cannot be written (run `uncluster agent install`). (#127)"}
	}
	if !running {
		return CheckResult{Name: "writer-service", Status: CheckFail,
			Message: "UnclusterPrincipalsWriter service not RUNNING — policy apply will fail (start: net start UnclusterPrincipalsWriter). (#127)"}
	}
	return CheckResult{Name: "writer-service", Status: CheckOK,
		Message: "UnclusterPrincipalsWriter (LocalSystem) installed and running"}
}

// spoolACLResult maps the resolved spool-dir ACL state to a CheckResult (#127).
// Healthy: the spool dir exists and grants the agent account write (so it can
// submit desired-state). spoolExists=false → fail (install not run). Pure
// mapping; the DACL read lives in the windows-tagged probe.
func spoolACLResult(dir string, spoolExists, agentCanWrite bool) CheckResult {
	if !spoolExists {
		return CheckResult{Name: "spool-dir", Status: CheckFail,
			Message: fmt.Sprintf("%s not found — the agent↔writer spool is missing (run `uncluster agent install`). (#127)", dir)}
	}
	if !agentCanWrite {
		return CheckResult{Name: "spool-dir", Status: CheckFail,
			Message: fmt.Sprintf("%s: NT SERVICE\\UnclusterAgent cannot write the spool — it cannot submit desired-state to the writer (run `uncluster agent install`). (#127)", dir)}
	}
	return CheckResult{Name: "spool-dir", Status: CheckOK,
		Message: fmt.Sprintf("spool dir ok at %s (agent can submit desired-state; SYSTEM owns it)", dir)}
}

// configACLProbe is the resolved DACL state for the Windows system config file.
type configACLProbe struct {
	exists      bool
	sidResolved bool
	grantsRead  bool
}

// configACLResult maps a resolved Windows system-config DACL probe to a
// CheckResult. Healthy: the file exists and `NT SERVICE\UnclusterAgent` has a
// read-granting ACE (install grants it via restrictSystemConfigACL). Absent
// file → warn (doctor may run before install copies the system path). SID
// unresolvable or no read grant → fail (the service cannot read its config and
// will not start, #77). Pure so the mapping is testable on every platform.
func configACLResult(path string, p configACLProbe) CheckResult {
	if !p.exists {
		return CheckResult{Name: "config-ownership", Status: CheckWarn,
			Message: fmt.Sprintf("%s absent (run `uncluster agent install` to populate the system path)", path)}
	}
	if !p.sidResolved {
		return CheckResult{Name: "config-ownership", Status: CheckFail,
			Message: fmt.Sprintf("%s: cannot resolve NT SERVICE\\UnclusterAgent (service not registered) — run `uncluster agent install`", path)}
	}
	if !p.grantsRead {
		return CheckResult{Name: "config-ownership", Status: CheckFail,
			Message: fmt.Sprintf("%s: NT SERVICE\\UnclusterAgent lacks read access (service cannot read config) — run `uncluster agent install`", path)}
	}
	return CheckResult{Name: "config-ownership", Status: CheckOK,
		Message: fmt.Sprintf("config ownership ok at %s (NT SERVICE\\UnclusterAgent has read)", path)}
}
