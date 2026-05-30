package validate

import (
	"strings"
	"testing"
)

// TestSelfUpdateValidation_HappyPath: a faked update to the target version
// succeeds and the agent comes back reporting the new version (#111). Evidence
// captures version-before/after.
func TestSelfUpdateValidation_HappyPath(t *testing.T) {
	cur := "v2.0.0"
	res := RunSelfUpdateValidation(SelfUpdateOpts{
		TargetVersion: "v2.0.1",
		VersionBefore: func() string { return "v2.0.0" },
		ApplyUpdate: func(target string) error {
			cur = target // faked binary swap to the target
			return nil
		},
		VersionAfter: func() string { return cur },
		Rollback: func() error {
			t.Error("rollback must NOT run on a successful update")
			return nil
		},
	})

	if res.State != "ok" {
		t.Errorf("happy-path State = %q, want ok\nraw: %s", res.State, res.Raw)
	}
	if !strings.Contains(res.Raw, "v2.0.0") || !strings.Contains(res.Raw, "v2.0.1") {
		t.Errorf("evidence should record version before (v2.0.0) and after (v2.0.1): %s", res.Raw)
	}
}

// TestSelfUpdateValidation_RollbackOnBrokenUpdate: a deliberately-broken update
// (ApplyUpdate errors) triggers rollback, and the agent reports the PRIOR
// version — the safety property self-update validation exists to confirm.
func TestSelfUpdateValidation_RollbackOnBrokenUpdate(t *testing.T) {
	cur := "v2.0.0"
	rolledBack := false
	res := RunSelfUpdateValidation(SelfUpdateOpts{
		TargetVersion: "v2.0.1-broken",
		VersionBefore: func() string { return "v2.0.0" },
		ApplyUpdate: func(target string) error {
			cur = "corrupt" // the broken binary is "installed" but won't run
			return errSimulatedBrokenUpdate
		},
		VersionAfter: func() string { return cur },
		Rollback: func() error {
			rolledBack = true
			cur = "v2.0.0" // revert to prior binary
			return nil
		},
	})

	if !rolledBack {
		t.Error("a broken update must trigger rollback")
	}
	// The validated outcome: the agent is back on the prior version. This is a
	// PASS for the rollback-safety check (the broken update was correctly
	// reverted), not a fail.
	if res.State != "ok" {
		t.Errorf("rollback-recovery State = %q, want ok (broken update correctly reverted)\nraw: %s", res.State, res.Raw)
	}
	if !strings.Contains(res.Raw, "rolled back") && !strings.Contains(res.Raw, "reverted") {
		t.Errorf("evidence should note the rollback: %s", res.Raw)
	}
}

// TestSelfUpdateValidation_FailsIfRollbackDoesNotRecover: if even the rollback
// fails to restore the prior version, that is a real FAIL (the machine is left
// on a bad binary).
func TestSelfUpdateValidation_FailsIfRollbackDoesNotRecover(t *testing.T) {
	res := RunSelfUpdateValidation(SelfUpdateOpts{
		TargetVersion: "v2.0.1-broken",
		VersionBefore: func() string { return "v2.0.0" },
		ApplyUpdate:   func(string) error { return errSimulatedBrokenUpdate },
		VersionAfter:  func() string { return "corrupt" }, // rollback didn't recover
		Rollback:      func() error { return nil },
	})
	if res.State != "fail" {
		t.Errorf("State = %q, want fail when rollback does not restore the prior version", res.State)
	}
}

// TestSelfUpdateValidation_FailsIfUpdateSucceedsButWrongVersion: the update
// reports success but the agent comes back on an unexpected version → fail
// (then rollback).
func TestSelfUpdateValidation_FailsIfUpdateSucceedsButWrongVersion(t *testing.T) {
	rolledBack := false
	res := RunSelfUpdateValidation(SelfUpdateOpts{
		TargetVersion: "v2.0.1",
		VersionBefore: func() string { return "v2.0.0" },
		ApplyUpdate:   func(string) error { return nil }, // "succeeds"
		VersionAfter:  func() string { return "v2.0.0" }, // but version didn't change
		Rollback:      func() error { rolledBack = true; return nil },
	})
	if res.State != "fail" {
		t.Errorf("State = %q, want fail when post-update version != target", res.State)
	}
	if !rolledBack {
		t.Error("a version mismatch should trigger rollback")
	}
}

// TestSelfUpdateValidation_NilFuncsAreFail guards a misconfigured invocation.
func TestSelfUpdateValidation_NilFuncsAreFail(t *testing.T) {
	res := RunSelfUpdateValidation(SelfUpdateOpts{TargetVersion: "v1"})
	if res.State != "fail" {
		t.Errorf("State = %q, want fail with nil funcs", res.State)
	}
}
