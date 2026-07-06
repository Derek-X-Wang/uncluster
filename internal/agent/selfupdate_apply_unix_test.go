//go:build !windows

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// withTempPayloadDir redirects the managed payload dir to a temp dir for the
// duration of the test, initialising the store skeleton.
func withTempPayloadDir(t *testing.T) *PayloadStore {
	t.Helper()
	dir := t.TempDir()
	prev := managedPayloadDirFn
	managedPayloadDirFn = func() string { return dir }
	t.Cleanup(func() { managedPayloadDirFn = prev })
	s := NewPayloadStore(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("payload store Init: %v", err)
	}
	return s
}

// assetServer serves a binary at /bin and its correct sha256 at /sum.
func assetServer(t *testing.T, content []byte) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256(content)
	hexSum := hex.EncodeToString(sum[:])
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bin":
			_, _ = w.Write(content)
		case "/sum":
			fmt.Fprintf(w, "%s  uncluster\n", hexSum)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func newApplyAgent(t *testing.T) *Agent {
	t.Helper()
	return &Agent{cfg: Config{}, logger: testLogger(t)}
}

// applyUpdate stages+activates the verified payload and writes a pending-update
// marker — it does NOT touch the running binary or restart the service.
func TestApplyUpdate_StagesActivatesAndMarks(t *testing.T) {
	s := withTempPayloadDir(t)
	// Seed an initial current version so previous is populated after activate.
	mustStageActivate(t, s, "v0.0.1", "OLD")

	content := []byte("NEW BINARY v0.0.2")
	ts := assetServer(t, content)
	a := newApplyAgent(t)

	if err := a.applyUpdate(context.Background(), "v0.0.2", ts.URL+"/bin", ts.URL+"/sum"); err != nil {
		t.Fatalf("applyUpdate: %v", err)
	}

	// current now points at v0.0.2 with the downloaded bytes.
	binPath, ver, err := s.Current()
	if err != nil || ver != "v0.0.2" {
		t.Fatalf("current = %q err=%v, want v0.0.2", ver, err)
	}
	got, _ := os.ReadFile(binPath)
	if string(got) != string(content) {
		t.Errorf("staged binary = %q, want %q", got, content)
	}
	// previous preserved for rollback.
	if _, pv, err := s.Previous(); err != nil || pv != "v0.0.1" {
		t.Errorf("previous = %q err=%v, want v0.0.1", pv, err)
	}
	// pending-update marker names the new version.
	mv, ok, err := readMarker(PendingUpdateMarkerPath())
	if err != nil || !ok || mv != "v0.0.2" {
		t.Errorf("pending marker = %q ok=%v err=%v, want v0.0.2", mv, ok, err)
	}
}

// A corrupt checksum blocks the update: nothing is staged/activated and no
// pending marker is written.
func TestApplyUpdate_CorruptChecksumDoesNotStage(t *testing.T) {
	s := withTempPayloadDir(t)
	mustStageActivate(t, s, "v0.0.1", "OLD")

	content := []byte("NEW BINARY v0.0.3")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bin":
			_, _ = w.Write(content)
		case "/sum":
			fmt.Fprintf(w, "%s  uncluster\n", "00000000000000000000000000000000000000000000000000000000deadbeef")
		}
	}))
	t.Cleanup(ts.Close)

	a := newApplyAgent(t)
	err := a.applyUpdate(context.Background(), "v0.0.3", ts.URL+"/bin", ts.URL+"/sum")
	if err == nil {
		t.Fatal("applyUpdate should fail on checksum mismatch")
	}
	// current unchanged; v0.0.3 not staged; no marker.
	if _, ver, _ := s.Current(); ver != "v0.0.1" {
		t.Errorf("current = %q, want v0.0.1 (unchanged)", ver)
	}
	if _, err := os.Stat(PendingUpdateMarkerPath()); !os.IsNotExist(err) {
		t.Error("pending marker must not be written on a corrupt update")
	}
}

// A quarantined version is refused before any download.
func TestApplyUpdate_RefusesQuarantined(t *testing.T) {
	s := withTempPayloadDir(t)
	mustStageActivate(t, s, "v0.0.1", "OLD")
	if err := s.Quarantine("v0.0.2"); err != nil {
		t.Fatal(err)
	}
	a := newApplyAgent(t)
	// A server that would panic if hit — proves we refuse before downloading.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("quarantined version must not trigger a download")
	}))
	t.Cleanup(ts.Close)

	err := a.applyUpdate(context.Background(), "v0.0.2", ts.URL+"/bin", ts.URL+"/sum")
	if err == nil {
		t.Fatal("applyUpdate should refuse a quarantined version")
	}
}
