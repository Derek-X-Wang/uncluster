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
// On Linux: systemctl restart uncluster-agent
//
// The agent process will be killed and restarted by the supervisor. Run()
// returns shortly after this call.
func (a *Agent) restartService(ctx context.Context) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "launchctl", "kickstart", "-k", "system/com.uncluster.agent")
	default:
		// Linux / systemd
		cmd = exec.CommandContext(ctx, "systemctl", "restart", "uncluster-agent")
	}
	a.logger.Info("selfupdate: triggering service restart", "os", runtime.GOOS)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("selfupdate: restart service: %w: %s", err, string(out))
	}
	return nil
}
