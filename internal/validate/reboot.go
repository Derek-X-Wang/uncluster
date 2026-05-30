package validate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Phase is where a reboot-survival run is in its two-phase lifecycle.
type Phase string

const (
	// PhaseArmed: Phase 1 completed (install ensured, marker armed, state
	// persisted, reboot triggered). The process that armed is expected to die
	// in the reboot; a fresh process resumes from the persisted state.
	PhaseArmed Phase = "armed"
	// PhaseDone: Phase 2 completed (resume verified resurrection). Terminal.
	PhaseDone Phase = "done"
)

// RebootState is the durable hand-off across the reboot boundary (#110,
// ADR-0009 decision 6). It is persisted to disk in Phase 1 and read by the
// fresh post-reboot process in Phase 2 — the reboot kills any in-process state,
// so disk is the only channel that survives.
type RebootState struct {
	RunID    string `json:"run_id"`
	Phase    Phase  `json:"phase"`
	Target   string `json:"target"`
	ArmedAt  int64  `json:"armed_at"` // unix seconds Phase 1 armed
	Evidence string `json:"evidence_path"`
}

// SaveRebootState persists the state atomically (write temp + rename) so a
// crash mid-write cannot leave a half-written state the resume can't parse.
func SaveRebootState(path string, st RebootState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadRebootState reads the persisted state. Returns (state, true, nil) when an
// armed run is present, (zero, false, nil) when there is none (nothing armed),
// or an error only on a genuinely unreadable/corrupt file.
func LoadRebootState(path string) (RebootState, bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return RebootState{}, false, nil
		}
		return RebootState{}, false, err
	}
	var st RebootState
	if err := json.Unmarshal(b, &st); err != nil {
		return RebootState{}, false, fmt.Errorf("corrupt reboot state %s: %w", path, err)
	}
	return st, true, nil
}

// ClearRebootState removes the persisted state (post-resume cleanup). Absent
// file is not an error.
func ClearRebootState(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// RebootSurvival orchestrates the two-phase reboot-survival check. The
// dangerous/OS-specific operations (install, reboot, liveness probe) are
// injectable so the state machine is unit-testable with a FAKED reboot boundary
// (process-kill + relaunch) — NO real reboot runs in CI. The real-reboot
// exercise is a deferred ready-for-human slice.
type RebootSurvival struct {
	StatePath string
	Target    string

	AllowReboot bool

	// EnsureInstalled makes sure the agent is installed before arming (Phase 1).
	EnsureInstalled func() error
	// TriggerReboot reboots the machine (Phase 1, only with AllowReboot). In
	// tests this is a fake; in production it runs the real reboot command.
	TriggerReboot func() error
	// VerifyResurrected checks the service came back + is heartbeating (Phase 2)
	// and returns (ok, evidence). In tests this is faked; in production it
	// probes launchctl/systemctl + the heartbeat.
	VerifyResurrected func() (ok bool, evidence string)
}

// ArmResult is what Arm reports.
type ArmResult struct {
	Phase Phase
	RunID string
}

// Arm runs Phase 1: ensure installed → persist armed state → trigger the
// reboot. It REFUSES (and triggers nothing, persists nothing) without
// AllowReboot — auto-reboot is never permitted implicitly (ADR-0009). The
// caller is expected to die in the reboot; Resume picks up from the persisted
// state.
func (r *RebootSurvival) Arm(runID, evidencePath string) (ArmResult, error) {
	if !r.AllowReboot {
		return ArmResult{}, fmt.Errorf("reboot-survival is disruptive: pass --allow-reboot to authorize the real reboot")
	}
	if r.EnsureInstalled != nil {
		if err := r.EnsureInstalled(); err != nil {
			return ArmResult{}, fmt.Errorf("ensure installed before arming: %w", err)
		}
	}
	st := RebootState{
		RunID:    runID,
		Phase:    PhaseArmed,
		Target:   r.Target,
		ArmedAt:  time.Now().Unix(),
		Evidence: evidencePath,
	}
	// Persist BEFORE triggering the reboot — if the reboot fires before the
	// state lands, the post-reboot process has nothing to resume from.
	if err := SaveRebootState(r.StatePath, st); err != nil {
		return ArmResult{}, fmt.Errorf("persist reboot state: %w", err)
	}
	if r.TriggerReboot != nil {
		if err := r.TriggerReboot(); err != nil {
			// Reboot trigger failed — roll back the armed state so we are not
			// left in a phantom "armed" state with no reboot coming.
			_ = ClearRebootState(r.StatePath)
			return ArmResult{}, fmt.Errorf("trigger reboot: %w", err)
		}
	}
	return ArmResult{Phase: PhaseArmed, RunID: runID}, nil
}

// ResumeResult is what Resume reports.
type ResumeResult struct {
	Armed    bool // was there a persisted armed run to resume?
	Passed   bool // did the service resurrect + heartbeat?
	RunID    string
	Evidence string
}

// Resume runs Phase 2: read the persisted state and, if a run was armed, verify
// the service resurrected + heartbeats, then clear the state. With no persisted
// state it is a clean no-op (nothing was armed). This is what a fresh
// post-reboot invocation calls.
func (r *RebootSurvival) Resume() (ResumeResult, error) {
	st, ok, err := LoadRebootState(r.StatePath)
	if err != nil {
		return ResumeResult{}, err
	}
	if !ok {
		return ResumeResult{Armed: false}, nil
	}

	passed := false
	evidence := "no verifier configured"
	if r.VerifyResurrected != nil {
		passed, evidence = r.VerifyResurrected()
	}

	// Clear the state regardless of verdict — the run is complete either way; a
	// failed resume should not re-trigger on the next invocation.
	if cerr := ClearRebootState(r.StatePath); cerr != nil {
		return ResumeResult{}, fmt.Errorf("clear reboot state after resume: %w", cerr)
	}

	return ResumeResult{
		Armed:    true,
		Passed:   passed,
		RunID:    st.RunID,
		Evidence: evidence,
	}, nil
}

// ResumeOrArm is the single-entry dispatcher a `validate --checks
// reboot-survival` invocation uses: if a run is already armed (persisted state
// present), it RESUMES (Phase 2 — verify resurrection); otherwise it ARMS
// (Phase 1 — persist + reboot). One repeated command thus auto-resumes after
// the reboot. Returns a CheckResult so it plugs into the validate CheckRunner.
//
// Phase 1 (arm) returns an "ok"-ish result whose message says a reboot was
// triggered and to re-run after reboot; in production the process is about to
// die in the reboot, so that message is mostly for the faked path. Phase 2
// (resume) returns "ok" iff the service resurrected + heartbeats, else "fail".
func (r *RebootSurvival) ResumeOrArm(runID, evidencePath string) CheckResult {
	const name = "reboot-survival"
	_, armed, err := LoadRebootState(r.StatePath)
	if err != nil {
		return CheckResult{Name: name, State: "fail", Raw: "read reboot state: " + err.Error()}
	}

	if armed {
		// Phase 2: resume.
		out, rerr := r.Resume()
		if rerr != nil {
			return CheckResult{Name: name, State: "fail", Raw: "resume failed: " + rerr.Error()}
		}
		if out.Passed {
			return CheckResult{Name: name, State: "ok",
				Raw: "reboot-survival PASSED: service resurrected after reboot — " + out.Evidence}
		}
		return CheckResult{Name: name, State: "fail",
			Raw: "reboot-survival FAILED: service did not resurrect after reboot — " + out.Evidence}
	}

	// Phase 1: arm. Refuses without --allow-reboot.
	if _, aerr := r.Arm(runID, evidencePath); aerr != nil {
		return CheckResult{Name: name, State: "fail", Raw: aerr.Error()}
	}
	return CheckResult{Name: name, State: "ok",
		Raw: "reboot-survival armed: state persisted + reboot triggered. Re-run `validate --checks reboot-survival` after the machine comes back to complete Phase 2."}
}

// DefaultRebootStatePath returns the durable reboot-survival state file
// alongside the breadcrumb in the state dir.
func DefaultRebootStatePath() (string, error) {
	bc, err := DefaultBreadcrumbPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(bc), "reboot-survival.json"), nil
}
