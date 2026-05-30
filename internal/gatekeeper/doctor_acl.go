package gatekeeper

import "fmt"

// principalsACLResult maps a resolved Windows principals-dir ACL probe to a
// CheckResult. Healthy install: the `NT SERVICE\UnclusterAgent` virtual account
// has a write-granting ACE on the dir (install grants it via icacls). doctor
// reads the DACL to determine this WITHOUT mutating the directory — the prior
// implementation write-probed (created+removed a temp file), violating the
// ADR-0009 `inspect` contract that lets the auto-invoke hook run doctor.
//
// sidResolved=false means `NT SERVICE\UnclusterAgent` could not be resolved at
// all → the service was never registered with SCM, so the grant cannot exist
// (fail, matching CI's hard `assert-principals-acl`). grantsWrite is only
// meaningful when sidResolved is true.
//
// Pure (no windows.* types) so the OK/Fail mapping is unit-testable on every
// platform; the DACL read + ACE enumeration lives in the windows-tagged probe.
func principalsACLResult(dir string, sidResolved, grantsWrite bool) CheckResult {
	if !sidResolved {
		return CheckResult{Name: "principals-dir", Status: CheckFail,
			Message: fmt.Sprintf("%s: cannot resolve NT SERVICE\\UnclusterAgent (service not registered) — run `uncluster agent install`", dir)}
	}
	if !grantsWrite {
		return CheckResult{Name: "principals-dir", Status: CheckFail,
			Message: fmt.Sprintf("%s: NT SERVICE\\UnclusterAgent lacks write access (run `uncluster agent install`)", dir)}
	}
	return CheckResult{Name: "principals-dir", Status: CheckOK,
		Message: fmt.Sprintf("principals dir ok at %s (NT SERVICE\\UnclusterAgent has write)", dir)}
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
