package validate

import (
	"fmt"
	"strings"
)

// InstallSmokeOpts configures the privileged install-smoke check (#109).
//
// Install and Verify are injectable so the orchestration — snapshot → install →
// verify → record, restore-on-failure — is unit-testable WITHOUT a real
// `sudo agent install`. In production Install runs the real
// `uncluster agent install` and Verify runs `uncluster agent doctor --json`;
// the first real-machine exercise is a deferred ready-for-human slice (#109's
// own scope).
type InstallSmokeOpts struct {
	// Footprint is the set of paths the install touches (ADR-0004: CA pubkey,
	// sshd drop-in, principals dir, system agent.toml). Snapshotted before the
	// install so a failure can be rolled back.
	Footprint []string
	// Install performs the install (real or faked). Required.
	Install func() error
	// Verify checks the install is healthy and returns (ok, doctorJSON). The
	// doctorJSON is captured into evidence. Required.
	Verify func() (ok bool, doctorJSON string)
}

// RunInstallSmoke is the privileged install-smoke check: it snapshots the
// install footprint, runs the install, verifies it with doctor, and — on an
// install OR an unhealthy-verify failure — restores from the snapshot so the
// machine is left clean (no half-install). The validation lock + the
// --allow-mutate gate are enforced by the Runner that dispatches this check;
// this function owns the snapshot/restore + install/verify sequencing.
//
// State: "ok" only when the install succeeded AND doctor reports healthy;
// "fail" (with the snapshot restored) otherwise.
func RunInstallSmoke(opts InstallSmokeOpts) CheckResult {
	const name = "install-smoke"
	if opts.Install == nil || opts.Verify == nil {
		return CheckResult{Name: name, State: "fail",
			Raw: "install-smoke misconfigured: Install and Verify are required"}
	}

	// 1. Preflight snapshot of the install footprint so any failure rolls back.
	snap, err := Snapshot(opts.Footprint)
	if err != nil {
		return CheckResult{Name: name, State: "fail",
			Raw: "preflight snapshot failed: " + err.Error()}
	}

	var log strings.Builder

	// 2. Run the install. On error, restore and bail (half-install rolled back).
	if err := opts.Install(); err != nil {
		fmt.Fprintf(&log, "install failed: %v\n", err)
		if rerr := snap.Restore(); rerr != nil {
			fmt.Fprintf(&log, "WARNING: restore after install failure also failed: %v\n", rerr)
		} else {
			log.WriteString("snapshot restored — machine left clean (no half-install)\n")
		}
		return CheckResult{Name: name, State: "fail", Raw: log.String()}
	}
	log.WriteString("install completed\n")

	// 3. Verify with doctor. An unhealthy install is a failure too → restore.
	ok, doctorJSON := opts.Verify()
	fmt.Fprintf(&log, "doctor verify: %s\n", doctorJSON)
	if !ok {
		log.WriteString("doctor reported the install unhealthy — rolling back\n")
		if rerr := snap.Restore(); rerr != nil {
			fmt.Fprintf(&log, "WARNING: restore after unhealthy verify also failed: %v\n", rerr)
		} else {
			log.WriteString("snapshot restored — unhealthy install rolled back\n")
		}
		return CheckResult{Name: name, State: "fail", Raw: log.String()}
	}

	log.WriteString("install verified healthy\n")
	return CheckResult{Name: name, State: "ok", Raw: log.String()}
}
