package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// emptyWipeDesiredState is the plain (non-deprovision) empty wipe a fail-closed
// apply submits — used to prove the deprovision flag, not emptiness, is what
// triggers writer self-removal.
func emptyWipeBytes(t *testing.T) []byte {
	t.Helper()
	b, err := marshalDesiredState(desiredStateFromPayload(api.PolicyPayload{Version: 0, Hash: "", Principals: nil}))
	if err != nil {
		t.Fatalf("marshal empty wipe: %v", err)
	}
	return b
}

// These tests cover the platform-neutral core of the #182 spool-mediated writer
// self-removal: the deprovision desired-state, its recognition across the
// (untrusted) privilege boundary, and the self-remove decision. The Windows-only
// service Delete() is validated on t2-windows; everything decision-shaped lives
// here so it runs on the CI Linux/dev-darwin host.

func TestDeprovisionDesiredState_Shape(t *testing.T) {
	d := deprovisionDesiredState()
	if !d.Deprovision {
		t.Fatal("deprovisionDesiredState must set Deprovision=true")
	}
	if d.Version != 0 || d.Hash != "" || len(d.Principals) != 0 {
		t.Fatalf("deprovision desired-state must be an empty wipe (version 0, hash \"\", no principals); got %+v", d)
	}
}

func TestDesiredState_DeprovisionRoundTrips(t *testing.T) {
	b, err := marshalDesiredState(deprovisionDesiredState())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := unmarshalDesiredState(b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Deprovision {
		t.Fatalf("Deprovision did not round-trip through the spool JSON: %s", b)
	}
}

func TestDesiredStateRequestsDeprovision(t *testing.T) {
	depro, _ := marshalDesiredState(deprovisionDesiredState())
	normalEmpty := emptyWipeBytes(t)
	cases := []struct {
		name string
		b    []byte
		want bool
	}{
		{"deprovision signal", depro, true},
		{"normal empty wipe (fail-closed)", normalEmpty, false},
		{"garbage bytes", []byte("}{not json"), false},
		{"empty bytes", nil, false},
		{"explicit false", []byte(`{"version":0,"deprovision":false}`), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := desiredStateRequestsDeprovision(tc.b); got != tc.want {
				t.Fatalf("desiredStateRequestsDeprovision(%s) = %v, want %v", tc.b, got, tc.want)
			}
		})
	}
}

func TestShouldSelfRemoveOnApply(t *testing.T) {
	depro, _ := marshalDesiredState(deprovisionDesiredState())
	normal := emptyWipeBytes(t)
	ok := appliedStatus{Status: "ok"}
	failed := appliedStatus{Status: "failed", Error: "boom"}

	// Self-remove ONLY when a deprovision signal was applied successfully.
	if !shouldSelfRemoveOnApply(depro, ok) {
		t.Fatal("deprovision + ok must self-remove")
	}
	if shouldSelfRemoveOnApply(depro, failed) {
		t.Fatal("deprovision + failed apply must NOT self-remove (wipe not confirmed)")
	}
	if shouldSelfRemoveOnApply(normal, ok) {
		t.Fatal("a normal (fail-closed) empty wipe must NOT self-remove the writer")
	}
}

// TestApplyDeprovisionState_WipesThenOK confirms the deprovision desired-state
// still drives a real wipe (empty render) with an ok status through the SAME
// core the writer uses — so the writer wipes principals BEFORE it self-removes.
func TestApplyDeprovisionState_WipesThenOK(t *testing.T) {
	dir := t.TempDir()
	// Pre-populate a per-user principals file.
	if err := os.WriteFile(filepath.Join(dir, "alice"), []byte("caller-x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, _ := marshalDesiredState(deprovisionDesiredState())
	st := applyDesiredStateBytes(dir, b)
	if st.Status != "ok" {
		t.Fatalf("deprovision apply status = %q (err %q), want ok", st.Status, st.Error)
	}
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		if !f.IsDir() {
			t.Fatalf("deprovision apply left principals file %q; expected an empty wipe", f.Name())
		}
	}
}
