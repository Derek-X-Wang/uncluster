//go:build !windows

package agent

import (
	"context"
	"log/slog"
	"os"
)

// RunLauncher is the entrypoint for `uncluster agent launch` — the service
// ExecStart target on Linux/macOS under the #187 hybrid-launcher model. It runs
// as the low-priv service account (the launcher binary is root-owned but wields
// no root runtime power), supervises the self-updatable payload from the managed
// store, and:
//
//   - requires each freshly-started version to commit health (config loaded +
//     first successful heartbeat, signalled via the health marker) within the
//     deadline; a version that exits early or misses it is rolled back to the
//     last-known-good and quarantined (≤30s, ADR-0006);
//   - watches the pending-update marker the payload writes after it stages+
//     activates a new version, and restarts the child onto it;
//   - terminates cleanly (no rollback) when the Agent was deprovisioned (the
//     payload wiped principals + wrote .deprovisioned + exited 0), and when the
//     service manager stops it (SIGTERM cancels ctx → the child is SIGTERM'd,
//     then SIGKILL'd after grace, and reaped).
//
// ctx should be a signal-aware context (the CLI wires SIGINT/SIGTERM) so a
// launchd/systemd stop drives a graceful shutdown.
func RunLauncher(ctx context.Context, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	store := NewPayloadStore(ManagedPayloadDir())
	markerPath := HealthMarkerPath()

	// Derive the .deprovisioned marker next to agent.toml so a revoked agent
	// terminates the launcher cleanly instead of flap-restarting.
	cfgPath, _ := ResolveConfigPath()
	deprovMarker := deprovisionedMarkerPath(cfgPath)

	logger.Info("launcher: supervising payload store",
		"payload_dir", store.Root(), "health_marker", markerPath,
		"pending_marker", PendingUpdateMarkerPath(), "deprovisioned_marker", deprovMarker)

	l := NewLauncher(LauncherConfig{
		Store:             store,
		Runner:            newExecRunner(markerPath, logger),
		Health:            newMarkerHealthWaiter(markerPath),
		Logger:            logger,
		PendingUpdatePath: PendingUpdateMarkerPath(),
		ShouldStop: func() bool {
			if deprovMarker == "" {
				return false
			}
			_, err := os.Stat(deprovMarker)
			return err == nil
		},
	})
	return l.Run(ctx)
}
