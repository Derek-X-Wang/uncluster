//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// applyUpdate performs the historical in-place self-update on Windows: swap the
// running binary and restart via the SCM. Windows binary relocation to a
// service-owned path (the analog of the #187 Unix payload store) is tracked
// separately in #139; until then Windows keeps its existing posture unchanged.
func (a *Agent) applyUpdate(ctx context.Context, expectedVersion, assetURL, sha256URL string) error {
	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("selfupdate: resolve executable: %w", err)
	}
	updater := NewUpdater(binaryPath, a.cfg.PinnedVersion, a.logger)
	if err := updater.Apply(ctx, expectedVersion, assetURL, sha256URL); err != nil {
		if errors.Is(err, ErrPinned) {
			return nil
		}
		return err
	}
	return a.restartService(ctx)
}
