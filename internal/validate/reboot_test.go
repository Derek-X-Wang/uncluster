package validate

import (
	"path/filepath"
	"testing"
)

// TestRebootState_PersistAndLoad verifies the two-phase state round-trips
// through disk — the durable handoff that lets a fresh post-reboot process
// pick up where the pre-reboot process left off (#110).
func TestRebootState_PersistAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reboot-survival.json")

	// No state yet → LoadRebootState reports "not armed".
	if st, ok, err := LoadRebootState(path); err != nil {
		t.Fatalf("LoadRebootState on missing file: %v", err)
	} else if ok {
		t.Errorf("LoadRebootState on missing file reported armed=%+v, want not armed", st)
	}

	want := RebootState{
		RunID:    "20260530T060000Z-abcd1234",
		Phase:    PhaseArmed,
		Target:   "this-machine",
		ArmedAt:  1780000000,
		Evidence: "/tmp/uncluster-validate/run/x",
	}
	if err := SaveRebootState(path, want); err != nil {
		t.Fatalf("SaveRebootState: %v", err)
	}
	got, ok, err := LoadRebootState(path)
	if err != nil {
		t.Fatalf("LoadRebootState: %v", err)
	}
	if !ok {
		t.Fatal("LoadRebootState reported not-armed after save")
	}
	if got != want {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}

	// ClearRebootState removes it (post-resume cleanup).
	if err := ClearRebootState(path); err != nil {
		t.Fatalf("ClearRebootState: %v", err)
	}
	if _, ok, _ := LoadRebootState(path); ok {
		t.Error("state still present after ClearRebootState")
	}
}

// TestRebootSurvival_RefusesRealRebootWithoutFlag asserts the disruptive gate:
// without --allow-reboot, arming must refuse and NOT call the reboot trigger.
func TestRebootSurvival_RefusesRealRebootWithoutFlag(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "reboot-survival.json")
	rebootCalled := false

	r := &RebootSurvival{
		StatePath:       statePath,
		Target:          "this-machine",
		AllowReboot:     false, // not authorized
		EnsureInstalled: func() error { return nil },
		TriggerReboot:   func() error { rebootCalled = true; return nil },
	}
	_, err := r.Arm("run-1", "/tmp/ev")
	if err == nil {
		t.Fatal("Arm without --allow-reboot should refuse")
	}
	if rebootCalled {
		t.Error("reboot was triggered despite --allow-reboot being absent")
	}
	// No state should be left armed on a refusal.
	if _, ok, _ := LoadRebootState(statePath); ok {
		t.Error("reboot state was armed despite the refusal")
	}
}

// TestRebootSurvival_ArmPersistsThenResumeVerifies walks the full two-phase
// flow IN-PROCESS with a faked reboot boundary (Arm persists state + "reboots"
// via the injected trigger; a separate Resume reads the persisted state and
// verifies liveness). The cross-process variant is TestRebootSurvival_ResumeAfterProcessDeath.
func TestRebootSurvival_ArmPersistsThenResumeVerifies(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "reboot-survival.json")

	// Phase 1: arm. The faked reboot trigger just records that it would reboot.
	rebooted := false
	armer := &RebootSurvival{
		StatePath:       statePath,
		Target:          "this-machine",
		AllowReboot:     true,
		EnsureInstalled: func() error { return nil },
		TriggerReboot:   func() error { rebooted = true; return nil },
	}
	res, err := armer.Arm("run-2", "/tmp/ev2")
	if err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if !rebooted {
		t.Error("Arm with --allow-reboot should have triggered the (faked) reboot")
	}
	if res.Phase != PhaseArmed {
		t.Errorf("after Arm, phase = %q, want armed", res.Phase)
	}
	// State must be persisted for the post-reboot process to find.
	if _, ok, _ := LoadRebootState(statePath); !ok {
		t.Fatal("Arm did not persist reboot state")
	}

	// Phase 2: a "fresh process" resumes. Service is alive + heartbeating.
	resumer := &RebootSurvival{
		StatePath: statePath,
		Target:    "this-machine",
		VerifyResurrected: func() (bool, string) {
			return true, "service PID 4321 alive; last heartbeat 3s ago"
		},
	}
	out, err := resumer.Resume()
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if !out.Passed {
		t.Errorf("Resume verdict Passed=false, want true (service resurrected)")
	}
	// State cleared after a completed resume.
	if _, ok, _ := LoadRebootState(statePath); ok {
		t.Error("reboot state not cleared after Resume")
	}
}

// TestRebootSurvival_ResumeFailsWhenServiceDead: Phase 2 must FAIL when the
// service did not come back after the reboot.
func TestRebootSurvival_ResumeFailsWhenServiceDead(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "reboot-survival.json")
	if err := SaveRebootState(statePath, RebootState{RunID: "r", Phase: PhaseArmed, Target: "this-machine", ArmedAt: 1}); err != nil {
		t.Fatal(err)
	}
	resumer := &RebootSurvival{
		StatePath:         statePath,
		VerifyResurrected: func() (bool, string) { return false, "service not loaded; no heartbeat" },
	}
	out, err := resumer.Resume()
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if out.Passed {
		t.Error("Resume should FAIL when the service did not resurrect")
	}
}

// TestRebootSurvival_ResumeWithoutArmedStateIsNoop: a Resume with no persisted
// state (nothing was armed) is a clean no-op, not a crash.
func TestRebootSurvival_ResumeWithoutArmedStateIsNoop(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "reboot-survival.json")
	r := &RebootSurvival{StatePath: statePath}
	out, err := r.Resume()
	if err != nil {
		t.Fatalf("Resume with no state should not error: %v", err)
	}
	if out.Armed {
		t.Error("Resume reported Armed=true with no persisted state")
	}
}
