//go:build windows

package agent

import (
	"context"
	"fmt"
	"os/exec"
)

// restartService on Windows restarts via the SCM.
func (a *Agent) restartService(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "net", "stop", WindowsServiceName)
	if out, err := cmd.CombinedOutput(); err != nil {
		a.logger.Warn("selfupdate: net stop returned error (may be ok)", "err", err, "out", string(out))
	}
	cmd2 := exec.CommandContext(ctx, "net", "start", WindowsServiceName)
	if out, err := cmd2.CombinedOutput(); err != nil {
		return fmt.Errorf("selfupdate: net start %s: %w: %s", WindowsServiceName, err, string(out))
	}
	return nil
}
