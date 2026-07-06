package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// This file defines the launcher↔payload coordination contract for the #187
// hybrid launcher. It is portable (no Unix-only syscalls) so the `agent run`
// hook that writes the health marker compiles on every platform; the env var is
// only ever set by the Unix launcher, so on Windows the hook is simply inert.
//
// Contract shape: both marker files carry a schema_version so the launcher and
// payload — which are DIFFERENT binary versions after an update (an old
// launcher supervising a newly-downloaded payload) — can evolve the contract
// without a flag day. A reader that does not recognise the schema_version treats
// the marker as absent (fail-safe: no false health commit, no phantom update).

// HealthMarkerEnv is the environment variable the launcher sets on the payload
// child, naming the path where the child must write its health-commit marker
// after its first successful heartbeat. Empty/unset (a plain `agent run` not
// launched by the supervisor, or Windows) means "no marker to write".
const HealthMarkerEnv = "UNCLUSTER_HEALTH_MARKER"

// HealthMarkerPathFromEnv returns the marker path the launcher assigned to this
// payload process, or "" if it was not launched under supervision.
func HealthMarkerPathFromEnv() string { return os.Getenv(HealthMarkerEnv) }

// markerSchemaVersion is the current launcher↔payload contract version. Bump
// only on an incompatible change; readers reject versions they do not know.
const markerSchemaVersion = 1

// markerBody is the shared, forward-compatible body of both the health marker
// and the pending-update marker.
type markerBody struct {
	// SchemaVersion is the contract version. A reader that does not recognise
	// it treats the marker as absent.
	SchemaVersion int `json:"schema_version"`
	// Version is the payload version the marker refers to: for the health
	// marker, the version that committed health; for the pending-update marker,
	// the newly-activated version to restart onto.
	Version string `json:"version"`
	// WrittenAtUnix is advisory (diagnostics only); seconds since the epoch.
	WrittenAtUnix int64 `json:"written_at_unix,omitempty"`
}

// writeMarkerAtomic writes body as JSON to path via a temp-file + rename so a
// reader never observes a torn write. The parent dir is created if missing (the
// service account owns the managed payload dir).
func writeMarkerAtomic(path string, body markerBody) error {
	body.SchemaVersion = markerSchemaVersion
	body.WrittenAtUnix = time.Now().Unix()
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marker: marshal: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("marker: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".marker-*")
	if err != nil {
		return fmt.Errorf("marker: create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("marker: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("marker: fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("marker: close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("marker: install %s: %w", path, err)
	}
	cleanup = false
	return nil
}

// readMarker reads and validates a marker file. It returns (version, true, nil)
// only when the file exists, parses, and carries the current schema version; a
// missing file returns ("", false, nil); a malformed or wrong-schema file
// returns ("", false, nil) too (fail-safe: unknown ⇒ absent). A genuine I/O
// error (not "not exist") is returned so the caller can log it.
func readMarker(path string) (version string, ok bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	var body markerBody
	if json.Unmarshal(data, &body) != nil {
		return "", false, nil
	}
	if body.SchemaVersion != markerSchemaVersion {
		return "", false, nil
	}
	return body.Version, true, nil
}

// WriteHealthMarker records that the running payload committed health by
// atomically writing its version (in the schema-versioned body) to path. Called
// by `agent run` after the first successful heartbeat when
// HealthMarkerPathFromEnv() is non-empty. A no-op when path is "" (unsupervised
// run). The version lets the launcher confirm the marker came from the version
// it actually started — not a stale marker from a prior boot or another version.
func WriteHealthMarker(path, version string) error {
	if path == "" {
		return nil
	}
	return writeMarkerAtomic(path, markerBody{Version: version})
}

// writePendingUpdateMarker records that a new version has been staged+activated
// and asks the launcher to restart the child onto it. Written by the Unix
// self-update handler after Activate.
func writePendingUpdateMarker(path, version string) error {
	return writeMarkerAtomic(path, markerBody{Version: version})
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
	got, ok, err := readMarker(w.path)
	return err == nil && ok && got == version
}
