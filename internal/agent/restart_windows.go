//go:build windows

package agent

import (
	"context"
	"fmt"
	"os/exec"
)

// restartService on Windows restarts via the SCM.
func (a *Agent) restartService(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "net", "stop", "UnclusterAgent")
	if out, err := cmd.CombinedOutput(); err != nil {
		a.logger.Warn("selfupdate: net stop returned error (may be ok)", "err", err, "out", string(out))
	}
	cmd2 := exec.CommandContext(ctx, "net", "start", "UnclusterAgent")
	if out, err := cmd2.CombinedOutput(); err != nil {
		return fmt.Errorf("selfupdate: net start UnclusterAgent: %w: %s", err, string(out))
	}
	return nil
}
