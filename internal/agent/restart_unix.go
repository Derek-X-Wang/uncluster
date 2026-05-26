//go:build !windows

package agent

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
)

// restartService triggers the platform supervisor to restart the agent service.
// On macOS: launchctl kickstart -k system/com.uncluster.agent
// On Linux: systemctl restart com.uncluster.agent
//
// The service unit name must match the one used at install time
// (gatekeeper/service_unix.go buildService → Name: "com.uncluster.agent").
// Previously this used the unqualified "uncluster-agent", which silently
// failed every self-update on Linux because no such systemd unit exists.
//
// The agent process will be killed and restarted by the supervisor. Run()
// returns shortly after this call.
func (a *Agent) restartService(ctx context.Context) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "launchctl", "kickstart", "-k", "system/com.uncluster.agent")
	default:
		// Linux / systemd — must match buildService Name.
		cmd = exec.CommandContext(ctx, "systemctl", "restart", "com.uncluster.agent")
	}
	a.logger.Info("selfupdate: triggering service restart", "os", runtime.GOOS)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("selfupdate: restart service: %w: %s", err, string(out))
	}
	return nil
}
