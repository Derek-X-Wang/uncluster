package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// healthMarkerEnv is the environment variable the launcher sets when spawning
// the payload child. The payload writes its own version to that path after its
// FIRST successful heartbeat (config loaded + control-plane reachable), which is
// the "health commit" the launcher waits for before considering an update good
// (#187). Empty/unset means "not supervised" — the payload writes nothing.
const healthMarkerEnv = "UNCLUSTER_HEALTH_MARKER"

// HealthMarkerPathFromEnv returns the marker path the launcher assigned to this
// payload process, or "" if it was not launched under supervision.
func HealthMarkerPathFromEnv() string { return os.Getenv(healthMarkerEnv) }

// WriteHealthMarker records that the running payload committed health by
// atomically writing its version to path. Called by `agent run` after the first
// successful heartbeat when HealthMarkerPathFromEnv() is non-empty. A no-op when
// path is "" (unsupervised run). The version is written so the launcher can
// confirm the marker came from the version it actually started — not a stale
// marker from a prior boot or a different version.
func WriteHealthMarker(path, version string) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("healthmarker: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".health-*")
	if err != nil {
		return fmt.Errorf("healthmarker: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(version); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("healthmarker: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("healthmarker: close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("healthmarker: install marker: %w", err)
	}
	return nil
}

// markerHealthWaiter is the production HealthWaiter: it polls the marker path
// until it holds the expected version, or ctx (the launcher's health deadline)
// fires. The exec runner clears the marker immediately before spawning each
// child, so a stale marker cannot satisfy the wait.
type markerHealthWaiter struct {
	path     string
	interval time.Duration
}

func newMarkerHealthWaiter(path string) *markerHealthWaiter {
	return &markerHealthWaiter{path: path, interval: 200 * time.Millisecond}
}

// clear removes any existing marker. Called before spawning a child so the wait
// only succeeds on a fresh, matching health commit.
func (w *markerHealthWaiter) clear() { _ = os.Remove(w.path) }

// WaitHealthy blocks until the marker holds version, or ctx is done.
func (w *markerHealthWaiter) WaitHealthy(ctx context.Context, version string) error {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		if w.matches(version) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (w *markerHealthWaiter) matches(version string) bool {
	b, err := os.ReadFile(w.path)
	return err == nil && strings.TrimSpace(string(b)) == version
}
