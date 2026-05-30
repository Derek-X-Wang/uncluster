package validate

import (
	"path/filepath"
	"testing"
)

// TestResumeOrArm_DispatchesByState verifies the single-entry dispatcher a
// `validate --checks reboot-survival` invocation uses: with no persisted state
// it ARMS (Phase 1); with persisted state it RESUMES (Phase 2). This is what
// makes one repeated command auto-resume after the reboot.
func TestResumeOrArm_DispatchesByState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "reboot-survival.json")

	armed := false
	resumed := false
	mk := func() *RebootSurvival {
		return &RebootSurvival{
			StatePath:       statePath,
			Target:          "this-machine",
			AllowReboot:     true,
			EnsureInstalled: func() error { return nil },
			TriggerReboot:   func() error { armed = true; return nil },
			VerifyResurrected: func() (bool, string) {
				resumed = true
				return true, "alive"
			},
		}
	}

	// First call: no state → arms. The CheckResult reflects the armed phase.
	first := mk().ResumeOrArm("run-x", "/tmp/ev")
	if !armed {
		t.Error("first ResumeOrArm should have armed (triggered reboot)")
	}
	if resumed {
		t.Error("first ResumeOrArm should NOT have resumed (nothing was armed yet)")
	}
	if first.State == "fail" {
		t.Errorf("arm phase should not be a failure: %s", first.Raw)
	}

	// Second call: persisted state exists → resumes + verifies.
	second := mk().ResumeOrArm("run-x", "/tmp/ev")
	if !resumed {
		t.Error("second ResumeOrArm should have resumed")
	}
	if second.State != "ok" {
		t.Errorf("resume of a resurrected service should be ok, got %q: %s", second.State, second.Raw)
	}
}

// TestResumeOrArm_RefusesWithoutAllowReboot: when arming would be required
// (no state) but --allow-reboot is absent, the dispatcher fails clearly and
// triggers nothing.
func TestResumeOrArm_RefusesWithoutAllowReboot(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "reboot-survival.json")
	triggered := false
	r := &RebootSurvival{
		StatePath:       statePath,
		Target:          "this-machine",
		AllowReboot:     false,
		EnsureInstalled: func() error { return nil },
		TriggerReboot:   func() error { triggered = true; return nil },
	}
	res := r.ResumeOrArm("run-y", "/tmp/ev")
	if res.State != "fail" {
		t.Errorf("ResumeOrArm without --allow-reboot should fail, got %q", res.State)
	}
	if triggered {
		t.Error("reboot triggered despite missing --allow-reboot")
	}
}
