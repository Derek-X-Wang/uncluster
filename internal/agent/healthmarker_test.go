package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteHealthMarker_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "health") // note: dir must be created

	if err := WriteHealthMarker(path, "v1.2.3"); err != nil {
		t.Fatalf("WriteHealthMarker: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if string(b) != "v1.2.3" {
		t.Errorf("marker content = %q, want v1.2.3", b)
	}
}

func TestWriteHealthMarker_EmptyPathIsNoop(t *testing.T) {
	if err := WriteHealthMarker("", "v1"); err != nil {
		t.Errorf("empty path should be a no-op, got %v", err)
	}
}

func TestMarkerHealthWaiter_SucceedsWhenVersionMatches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "health")
	w := newMarkerHealthWaiter(path)
	w.interval = 5 * time.Millisecond

	// Write the matching marker shortly after starting the wait.
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = WriteHealthMarker(path, "v2")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := w.WaitHealthy(ctx, "v2"); err != nil {
		t.Errorf("WaitHealthy should succeed once marker matches, got %v", err)
	}
}

func TestMarkerHealthWaiter_TimesOutOnWrongVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "health")
	// A stale/wrong-version marker must NOT satisfy the wait.
	if err := WriteHealthMarker(path, "OLD"); err != nil {
		t.Fatal(err)
	}
	w := newMarkerHealthWaiter(path)
	w.interval = 5 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if err := w.WaitHealthy(ctx, "NEW"); err == nil {
		t.Error("WaitHealthy should time out when marker holds a different version")
	}
}

func TestMarkerHealthWaiter_ClearRemovesStale(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "health")
	if err := WriteHealthMarker(path, "v1"); err != nil {
		t.Fatal(err)
	}
	w := newMarkerHealthWaiter(path)
	w.clear()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("clear did not remove the marker")
	}
	// After clear, a wait for the old version must time out (not match a stale file).
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	w.interval = 5 * time.Millisecond
	if err := w.WaitHealthy(ctx, "v1"); err == nil {
		t.Error("WaitHealthy matched a cleared marker")
	}
}

func TestHealthMarkerPathFromEnv(t *testing.T) {
	t.Setenv(healthMarkerEnv, "/tmp/x/health")
	if got := HealthMarkerPathFromEnv(); got != "/tmp/x/health" {
		t.Errorf("HealthMarkerPathFromEnv = %q, want /tmp/x/health", got)
	}
}
