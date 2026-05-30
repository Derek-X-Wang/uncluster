package validate

import (
	"errors"
	"fmt"
	"strings"
)

// errSimulatedBrokenUpdate is used by tests to model a broken update artifact.
var errSimulatedBrokenUpdate = errors.New("simulated broken update")

// SelfUpdateOpts configures the self-update validation check (#111).
//
// The version probes + the swap/rollback are injectable so the happy AND
// rollback paths are unit-testable with FAKED update artifacts + a faked binary
// swap — no real self-update runs in CI. In production these wrap the real
// update flow (download → checksum → atomic swap → restart) and a `--version`
// probe; the real-machine exercise is a deferred ready-for-human slice.
type SelfUpdateOpts struct {
	// TargetVersion is the version the update should land on.
	TargetVersion string
	// VersionBefore reports the agent's version prior to the update.
	VersionBefore func() string
	// ApplyUpdate performs the update to target (real or faked binary swap). A
	// returned error models a broken/aborted update.
	ApplyUpdate func(target string) error
	// VersionAfter reports the agent's version after the update (or rollback).
	VersionAfter func() string
	// Rollback reverts to the prior binary. Invoked when the update is broken
	// or lands on the wrong version.
	Rollback func() error
}

// RunSelfUpdateValidation validates the self-update flow + its rollback safety
// (#111). It records version-before, applies the update, and checks the agent
// came back on the target version. If the update is broken (ApplyUpdate errors)
// OR lands on the wrong version, it triggers rollback and PASSES iff the agent
// is restored to the prior version — i.e. the rollback-safety property held. It
// FAILS only when even the rollback cannot restore a good binary (the machine
// is left broken).
//
// State: "ok" = either a clean update to target, or a broken update correctly
// reverted to the prior version. "fail" = wrong-version-and-rollback-failed, or
// a misconfigured invocation.
func RunSelfUpdateValidation(opts SelfUpdateOpts) CheckResult {
	const name = "self-update"
	if opts.VersionBefore == nil || opts.ApplyUpdate == nil || opts.VersionAfter == nil || opts.Rollback == nil {
		return CheckResult{Name: name, State: "fail",
			Raw: "self-update misconfigured: VersionBefore, ApplyUpdate, VersionAfter, Rollback are all required"}
	}

	var log strings.Builder
	before := opts.VersionBefore()
	fmt.Fprintf(&log, "version before: %s\n", before)
	fmt.Fprintf(&log, "target version: %s\n", opts.TargetVersion)

	applyErr := opts.ApplyUpdate(opts.TargetVersion)
	if applyErr != nil {
		// EXPLICIT broken update (download/checksum/swap aborted). The
		// rollback-safety property is what we validate here: a broken update
		// must revert to the prior binary. PASS iff it does.
		fmt.Fprintf(&log, "update FAILED to apply: %v\n", applyErr)
		return rollbackAndVerify(name, &log, opts, before, true /*expectRecoveryPass*/)
	}

	after := opts.VersionAfter()
	fmt.Fprintf(&log, "version after update: %s\n", after)
	if after == opts.TargetVersion {
		log.WriteString("self-update PASSED: agent came back on the target version\n")
		return CheckResult{Name: name, State: "ok", Raw: log.String()}
	}

	// SILENT failure: ApplyUpdate claimed success but the agent is NOT on the
	// target version. This is a worse bug than an honest abort — a self-update
	// that lies about success — so it is a FAIL even if the rollback recovers.
	// We still roll back to leave the machine clean, but the verdict is fail.
	fmt.Fprintf(&log, "version mismatch: got %s, want %s (update claimed success) — rolling back, but this is a FAIL\n", after, opts.TargetVersion)
	return rollbackAndVerify(name, &log, opts, before, false /*expectRecoveryPass*/)
}

// rollbackAndVerify performs the rollback and leaves the machine clean.
//
// expectRecoveryPass distinguishes the two failure modes:
//   - true  (honest broken update): the validated property is rollback safety,
//     so a successful revert to the prior version is a PASS.
//   - false (silent wrong-version, update lied about success): always a FAIL —
//     we still roll back to keep the machine clean, but a lying updater is a
//     product bug. A failed rollback is a FAIL in both modes.
func rollbackAndVerify(name string, log *strings.Builder, opts SelfUpdateOpts, before string, expectRecoveryPass bool) CheckResult {
	if err := opts.Rollback(); err != nil {
		fmt.Fprintf(log, "ROLLBACK FAILED: %v\n", err)
		return CheckResult{Name: name, State: "fail", Raw: log.String()}
	}
	restored := opts.VersionAfter()
	fmt.Fprintf(log, "version after rollback: %s\n", restored)
	if restored != before {
		fmt.Fprintf(log, "self-update FAILED: rollback did not restore the prior version (got %s, want %s) — machine left on a bad binary\n", restored, before)
		return CheckResult{Name: name, State: "fail", Raw: log.String()}
	}
	if !expectRecoveryPass {
		fmt.Fprintf(log, "self-update FAILED: update silently landed the wrong version; reverted to %s but the updater cannot be trusted\n", before)
		return CheckResult{Name: name, State: "fail", Raw: log.String()}
	}
	fmt.Fprintf(log, "self-update rollback PASSED: broken update reverted; agent back on prior version %s\n", before)
	return CheckResult{Name: name, State: "ok", Raw: log.String()}
}
