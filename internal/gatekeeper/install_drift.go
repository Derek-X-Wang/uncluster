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
func detectServiceUnitDrift(content, intendedExe, intendedUser string) string {
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
	// Arguments: all three flavours include "agent" and "run" as literal
	// tokens (systemd ExecStart appends them, launchd plist <string>s, and
	// Windows BINARY_PATH_NAME quotes them).
	for _, arg := range []string{"agent", "run"} {
		if !strings.Contains(content, arg) {
			return fmt.Sprintf("argument drift: unit does not reference %q", arg)
		}
	}
	return ""
}
