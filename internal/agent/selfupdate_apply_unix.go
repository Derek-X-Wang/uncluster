//go:build !windows

package agent

import (
	"context"
	"fmt"
	"os"
)

// applyUpdate performs the #187 hybrid-launcher self-update on Linux/macOS: the
// low-priv Agent stages the verified new binary into the managed, service-
// writable payload store, activates it (atomic current-pointer swap), and writes
// a pending-update marker. The root-owned launcher — NOT the Agent — then
// restarts the child onto the new version and requires a health commit within
// its deadline, rolling back + quarantining on failure. The Agent never writes a
// root-owned binary and never restarts the system service (both need privileges
// it does not have under ADR-0004).
func (a *Agent) applyUpdate(ctx context.Context, expectedVersion, assetURL, sha256URL string) error {
	store := NewPayloadStore(ManagedPayloadDir())

	// Refuse a version the launcher previously quarantined for failing its
	// health commit — otherwise the Agent would re-download and re-activate the
	// same bad binary on every heartbeat while the Control plane still advertises
	// it (#187 spec item 1).
	if store.IsQuarantined(expectedVersion) {
		a.logger.Warn("selfupdate: refusing quarantined version",
			"component", "selfupdate", "version", expectedVersion)
		return fmt.Errorf("selfupdate: version %q is quarantined (failed a prior health commit); not re-activating", expectedVersion)
	}

	updater := NewUpdater("", a.cfg.PinnedVersion, a.logger)
	tmpPath, err := updater.downloadVerified(ctx, assetURL, sha256URL)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmpPath) }()

	f, err := os.Open(tmpPath)
	if err != nil {
		return fmt.Errorf("selfupdate: open verified download: %w", err)
	}
	defer f.Close()

	if _, err := store.Stage(expectedVersion, f); err != nil {
		return fmt.Errorf("selfupdate: stage payload: %w", err)
	}
	if err := store.Activate(expectedVersion); err != nil {
		return fmt.Errorf("selfupdate: activate payload: %w", err)
	}

	// Ask the launcher to restart the child onto the newly-activated version.
	if err := writePendingUpdateMarker(PendingUpdateMarkerPath(), expectedVersion); err != nil {
		return fmt.Errorf("selfupdate: write pending-update marker: %w", err)
	}

	a.logger.Info("selfupdate: staged and activated new payload; launcher will restart onto it",
		"component", "selfupdate", "version", expectedVersion,
		"payload_dir", store.Root(), "pending_marker", PendingUpdateMarkerPath())
	return nil
}
