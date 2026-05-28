//go:build !windows

package agent

import (
	"fmt"
	"os"
	"os/exec"
)

// restrictConfigACL on Unix is a no-op — mode 0600 is applied at write time
// in SaveConfig via OpenFile with perm 0o600.
func restrictConfigACL(_ string) error { return nil }

// restrictSystemConfigACL adjusts the system-wide config so the unprivileged
// `uncluster` service account can read it.
//
// Linux+darwin: change file ownership to root:uncluster, mode already 0640
// (set by SaveConfigSystem). If the `uncluster` group does not yet exist
// (install hasn't created the service account), this is a no-op so install
// can call ensureServiceAccount first then re-invoke this.
func restrictSystemConfigACL(path string) error {
	group := lookupServiceGroup()
	if group == "" {
		return nil // service account group not yet created; caller retries after install
	}
	if err := exec.Command("chown", "root:"+group, path).Run(); err != nil {
		return fmt.Errorf("chown root:%s %s: %w", group, path, err)
	}
	// Defensive: ensure mode is 0640 even if some umask interfered.
	if err := os.Chmod(path, 0o640); err != nil {
		return fmt.Errorf("chmod 0640 %s: %w", path, err)
	}
	return nil
}

// lookupServiceGroup returns the Unix group name the agent service runs as,
// or empty string if the group does not exist on this system. Probing via
// `getent group` is portable across glibc/musl. Falls back to `dscl` on
// macOS (where getent does not exist).
func lookupServiceGroup() string {
	for _, name := range []string{"uncluster", "_uncluster"} {
		if exec.Command("getent", "group", name).Run() == nil {
			return name
		}
		if exec.Command("dscl", ".", "-read", "/Groups/"+name).Run() == nil {
			return name
		}
	}
	return ""
}
