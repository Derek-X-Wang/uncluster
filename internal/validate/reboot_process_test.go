package validate

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestRebootSurvival_ResumeAfterProcessDeath is the load-bearing #110 test: the
// two-phase state machine must survive PROCESS DEATH, not just an in-process
// hand-off. We simulate the reboot boundary by actually killing the arming
// process and relaunching a SEPARATE process that resumes against the persisted
// state on disk.
//
// Mechanism: the test re-execs its own test binary in a subprocess with an env
// var selecting a helper that (a) arms then exits hard (os.Exit, no graceful
// return — modelling the reboot killing the process), and (b) a second
// subprocess that resumes. State is handed over only through the on-disk file.
func TestRebootSurvival_ResumeAfterProcessDeath(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "reboot-survival.json")

	// Subprocess 1: arm + die (simulating the reboot killing the process).
	armCmd := exec.Command(os.Args[0], "-test.run=TestRebootHelperProcess")
	armCmd.Env = append(os.Environ(),
		"UNCLUSTER_REBOOT_HELPER=arm",
		"UNCLUSTER_REBOOT_STATE="+statePath,
	)
	out, err := armCmd.CombinedOutput()
	// The helper calls os.Exit(0) after arming, so the subprocess exits 0.
	if err != nil {
		t.Fatalf("arm subprocess failed: %v\n%s", err, out)
	}

	// The arming process is now DEAD. The only thing that survived is the
	// on-disk state. Confirm it is there.
	if _, ok, lerr := LoadRebootState(statePath); lerr != nil || !ok {
		t.Fatalf("reboot state did not survive the arming process death (ok=%v err=%v)", ok, lerr)
	}

	// Subprocess 2: a FRESH process resumes from the persisted state.
	resumeCmd := exec.Command(os.Args[0], "-test.run=TestRebootHelperProcess")
	resumeCmd.Env = append(os.Environ(),
		"UNCLUSTER_REBOOT_HELPER=resume",
		"UNCLUSTER_REBOOT_STATE="+statePath,
	)
	rout, rerr := resumeCmd.CombinedOutput()
	if rerr != nil {
		t.Fatalf("resume subprocess failed: %v\n%s", rerr, rout)
	}

	// The resume helper exits 0 only when it successfully resumed an armed run
	// and verified resurrection. State must be cleared afterward.
	if _, ok, _ := LoadRebootState(statePath); ok {
		t.Errorf("reboot state not cleared after a successful cross-process resume\nresume output:\n%s", rout)
	}
}

// TestRebootHelperProcess is not a real test — it is the subprocess entry point
// re-execed by TestRebootSurvival_ResumeAfterProcessDeath. It does nothing
// unless the UNCLUSTER_REBOOT_HELPER env var selects a role, so it is a no-op in
// a normal test run.
func TestRebootHelperProcess(t *testing.T) {
	role := os.Getenv("UNCLUSTER_REBOOT_HELPER")
	if role == "" {
		return // normal run — not the subprocess
	}
	statePath := os.Getenv("UNCLUSTER_REBOOT_STATE")

	switch role {
	case "arm":
		r := &RebootSurvival{
			StatePath:       statePath,
			Target:          "this-machine",
			AllowReboot:     true,
			EnsureInstalled: func() error { return nil },
			// The "reboot" is this process dying below — the trigger is a no-op
			// here; what matters is that state was persisted before death.
			TriggerReboot: func() error { return nil },
		}
		if _, err := r.Arm("xproc-run", "/tmp/ev-xproc"); err != nil {
			os.Stderr.WriteString("arm failed: " + err.Error() + "\n")
			os.Exit(1)
		}
		// Die HARD — model the reboot killing the process mid-flight. No
		// deferred cleanup runs; only the on-disk state survives.
		os.Exit(0)

	case "resume":
		r := &RebootSurvival{
			StatePath: statePath,
			Target:    "this-machine",
			VerifyResurrected: func() (bool, string) {
				return true, "service alive + heartbeating (faked)"
			},
		}
		out, err := r.Resume()
		if err != nil {
			os.Stderr.WriteString("resume errored: " + err.Error() + "\n")
			os.Exit(1)
		}
		if !out.Armed {
			os.Stderr.WriteString("resume found no armed state\n")
			os.Exit(2)
		}
		if !out.Passed {
			os.Stderr.WriteString("resume verdict FAIL\n")
			os.Exit(3)
		}
		os.Exit(0)
	}
}
