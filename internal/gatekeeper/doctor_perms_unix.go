//go:build !windows

package gatekeeper

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// principalsDirStat is the subset of stat data the principals-dir owner/group/
// mode check reasons about. Split from the os.Stat probe so the OK/Fail mapping
// is deterministically unit-testable (the syscall.Stat_t + uid/gid→name lookup
// is integration-only).
type principalsDirStat struct {
	owner string
	group string
	mode  os.FileMode // permission bits only
}

// principalsDirMinMode is the minimum permission set install grants the
// principals dir: rwx for owner, rwx for group (so the service account can
// write principal files), r-x for others. CI asserts exactly 0775; doctor
// accepts >= group-write so a future, tighter-but-still-writable mode does not
// regress, while a mode that strips group-write (the silent-failure CI guards
// against) fails.
const principalsDirGroupWrite = 0o020 // group write bit

// principalsDirResult maps resolved principals-dir stat data to a CheckResult.
// Healthy install (per install_unix.go + CI's assert-principals-dir-perms):
// owner root, group == the service account group, group-writable mode. A
// mismatch on any axis is a hard fail because it means the low-priv service
// account cannot write principal files — the ACL→Policy sync silently breaks.
func principalsDirResult(dir string, st principalsDirStat, wantGroup string) CheckResult {
	var problems []string
	if st.owner != "root" {
		problems = append(problems, fmt.Sprintf("owner %q (want root)", st.owner))
	}
	if st.group != wantGroup {
		problems = append(problems, fmt.Sprintf("group %q (want %q)", st.group, wantGroup))
	}
	if st.mode&principalsDirGroupWrite == 0 {
		problems = append(problems, fmt.Sprintf("mode %#o not group-writable (service account cannot write principals)", st.mode))
	}
	if len(problems) > 0 {
		return CheckResult{Name: "principals-dir", Status: CheckFail,
			Message: fmt.Sprintf("%s: %s", dir, joinProblems(problems))}
	}
	return CheckResult{Name: "principals-dir", Status: CheckOK,
		Message: fmt.Sprintf("principals dir ok at %s (root:%s %#o)", dir, st.group, st.mode)}
}

// configOwnerStat mirrors principalsDirStat for the system config file.
type configOwnerStat struct {
	owner string
	group string
	mode  os.FileMode
}

// configOwnershipMaxMode is the most-permissive mode a healthy system
// agent.toml may carry. The config holds the durable Agent token, so anything
// readable by "other" (the world bit) is a fail. Install writes 0640
// (root:<service account>); doctor fails if the world-read bit is set or if
// ownership drifted off the service-account group (the #96 silent-no-op that
// leaves the config unreadable by the service account).
const configWorldRead = 0o004 // other read bit

// configOwnershipResult maps resolved system-config stat data to a CheckResult.
// Healthy: owner root, group == the service account group, not world-readable.
// Group mismatch is the #96 bug (group record absent → chown no-ops → service
// account cannot read its config → service fails to start); world-readability
// would expose the Agent token.
func configOwnershipResult(path string, st configOwnerStat, wantGroup string) CheckResult {
	var problems []string
	if st.owner != "root" {
		problems = append(problems, fmt.Sprintf("owner %q (want root)", st.owner))
	}
	if st.group != wantGroup {
		problems = append(problems, fmt.Sprintf("group %q (want %q — config unreadable by service account)", st.group, wantGroup))
	}
	if st.mode&configWorldRead != 0 {
		problems = append(problems, fmt.Sprintf("mode %#o is world-readable (exposes agent token)", st.mode))
	}
	if len(problems) > 0 {
		return CheckResult{Name: "config-ownership", Status: CheckFail,
			Message: fmt.Sprintf("%s: %s", path, joinProblems(problems))}
	}
	return CheckResult{Name: "config-ownership", Status: CheckOK,
		Message: fmt.Sprintf("config ownership ok at %s (root:%s %#o)", path, st.group, st.mode)}
}

func joinProblems(p []string) string {
	out := ""
	for i, s := range p {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}

// checkPrincipalsDirPerms stats the principals dir and delegates to
// principalsDirResult. Existence/is-dir failures short-circuit to a fail before
// the owner/group/mode comparison. wantGroup is the resolved service-account
// group ("" when the group record is absent — then the group check is skipped
// because service-group already reports that condition as its own check).
func checkPrincipalsDirPerms(dir, wantGroup string) CheckResult {
	info, err := os.Stat(dir)
	if err != nil {
		return CheckResult{Name: "principals-dir", Status: CheckFail,
			Message: fmt.Sprintf("missing %s: %v", dir, err)}
	}
	if !info.IsDir() {
		return CheckResult{Name: "principals-dir", Status: CheckFail,
			Message: fmt.Sprintf("%s exists but is not a directory", dir)}
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Platform without syscall.Stat_t (should not happen on unix). Keep the
		// existence/is-dir signal rather than crashing.
		return CheckResult{Name: "principals-dir", Status: CheckOK,
			Message: fmt.Sprintf("principals dir ok at %s (perms unverified on this platform)", dir)}
	}
	owner := lookupUserName(st.Uid)
	group := lookupGroupName(st.Gid)
	if wantGroup == "" {
		// service-group check already surfaces the absent-group condition; do
		// not double-report it here — compare against the resolved group so
		// only owner/mode are graded.
		wantGroup = group
	}
	return principalsDirResult(dir, principalsDirStat{
		owner: owner, group: group, mode: info.Mode().Perm(),
	}, wantGroup)
}

// checkConfigOwnership stats the system config file and delegates to
// configOwnershipResult. The system path is only present after install copies
// it there; on a pre-install / per-user-only host the file is absent and the
// check reports warn (informational) rather than fail, because doctor may run
// before install.
func checkConfigOwnership(path, wantGroup string) CheckResult {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return CheckResult{Name: "config-ownership", Status: CheckWarn,
				Message: fmt.Sprintf("%s absent (run `uncluster agent install` to populate the system path)", path)}
		}
		return CheckResult{Name: "config-ownership", Status: CheckFail,
			Message: fmt.Sprintf("stat %s: %v", path, err)}
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return CheckResult{Name: "config-ownership", Status: CheckOK,
			Message: fmt.Sprintf("config ownership ok at %s (perms unverified on this platform)", path)}
	}
	owner := lookupUserName(st.Uid)
	group := lookupGroupName(st.Gid)
	if wantGroup == "" {
		wantGroup = group
	}
	return configOwnershipResult(path, configOwnerStat{
		owner: owner, group: group, mode: info.Mode().Perm(),
	}, wantGroup)
}

// lookupUserName resolves a uid to a username, falling back to the numeric form
// if the lookup fails (e.g. the account was removed). Never returns "".
func lookupUserName(uid uint32) string {
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		return u.Username
	}
	return strconv.FormatUint(uint64(uid), 10)
}

// lookupGroupName resolves a gid to a group name, falling back to the numeric
// form on failure.
func lookupGroupName(gid uint32) string {
	if g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10)); err == nil {
		return g.Name
	}
	return strconv.FormatUint(uint64(gid), 10)
}
