package gatekeeper

import (
	"fmt"
	"strings"
)

// detectServiceUnitDrift inspects a service-unit file's content (systemd
// .service, launchd .plist, or `sc qc` output on Windows) for the intended
// executable path, username, and command arguments. Returns "" if none
// have drifted, otherwise a human-readable description of the first drift
// found. Cross-platform — extracted from install_unix.go so the Windows
// installer can share it (#50).
// intendedArgs are the sub-command tokens the unit should carry (e.g.
// {"agent","launch"} for the Unix launcher, {"agent","run"} for the Windows
// agent, {"principals-writer","run"} for the Windows writer). Passing them
// explicitly — rather than hardcoding "agent"/"run" — keeps drift detection
// correct after #187 relocated the Unix service to `agent launch`.
func detectServiceUnitDrift(content, intendedExe, intendedUser string, intendedArgs ...string) string {
	// Executable path: present in systemd ExecStart, launchd
	// ProgramArguments[0], or Windows SCM BINARY_PATH_NAME. If the unit
	// content doesn't contain the intended path verbatim, it drifted.
	if !strings.Contains(content, intendedExe) {
		return fmt.Sprintf("executable path drift: unit does not reference %q", intendedExe)
	}
	// User: systemd User=, launchd UserName key, or Windows SCM
	// SERVICE_START_NAME. The username string is distinctive enough that
	// a substring check is sufficient.
	if intendedUser != "" && !strings.Contains(content, intendedUser) {
		return fmt.Sprintf("user drift: unit does not reference %q", intendedUser)
	}
	// Arguments: the caller-supplied sub-command tokens (systemd ExecStart
	// appends them, launchd plist <string>s, and Windows BINARY_PATH_NAME quotes
	// them).
	for _, arg := range intendedArgs {
		if !strings.Contains(content, arg) {
			return fmt.Sprintf("argument drift: unit does not reference %q", arg)
		}
	}
	return ""
}
