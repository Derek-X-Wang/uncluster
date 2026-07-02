//go:build !windows

package gatekeeper

import (
	"errors"
	"testing"
)

type recordedCall struct {
	name string
	args []string
}

// withFakeServiceRunner swaps runServiceCmd for a fake that records every call
// and returns errFn(name, args) for each (nil errFn = every call succeeds). The
// original is restored on cleanup. This is the launchctl package-var fake
// pattern applied to the systemctl/sshd probes, giving them their first no-root
// coverage (#151).
func withFakeServiceRunner(t *testing.T, errFn func(name string, args []string) error) *[]recordedCall {
	t.Helper()
	var calls []recordedCall
	orig := runServiceCmd
	runServiceCmd = func(name string, args ...string) error {
		calls = append(calls, recordedCall{name: name, args: append([]string(nil), args...)})
		if errFn != nil {
			return errFn(name, args)
		}
		return nil
	}
	t.Cleanup(func() { runServiceCmd = orig })
	return &calls
}

func argsContain(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// TestAgentServiceNameConstant locks the single service-name value so a future
// drift (the very thing this constant prevents) is caught.
func TestAgentServiceNameConstant(t *testing.T) {
	if agentServiceName != "com.uncluster.agent" {
		t.Fatalf("agentServiceName = %q, want com.uncluster.agent", agentServiceName)
	}
}

// TestCheckServiceRunning_OKWhenRunnerSucceeds drives the doctor service-status
// check through a succeeding fake runner and asserts the probe references the
// single service-name constant.
func TestCheckServiceRunning_OKWhenRunnerSucceeds(t *testing.T) {
	calls := withFakeServiceRunner(t, nil)

	got := checkServiceRunning()
	if got.Status != CheckOK {
		t.Fatalf("status = %v, want CheckOK", got.Status)
	}
	if len(*calls) != 1 {
		t.Fatalf("runner calls = %d, want exactly 1", len(*calls))
	}
	if !argsContain((*calls)[0].args, agentServiceName) {
		t.Errorf("probe args %v do not reference agentServiceName %q", (*calls)[0].args, agentServiceName)
	}
}

// TestCheckServiceRunning_FailWhenRunnerFails asserts a failing probe maps to a
// CheckFail result.
func TestCheckServiceRunning_FailWhenRunnerFails(t *testing.T) {
	withFakeServiceRunner(t, func(string, []string) error { return errors.New("inactive") })

	if got := checkServiceRunning(); got.Status != CheckFail {
		t.Fatalf("status = %v, want CheckFail", got.Status)
	}
}

// TestCheckSSHDRunning_OKWhenRunnerSucceeds drives the sshd-running doctor check
// through a succeeding runner.
func TestCheckSSHDRunning_OKWhenRunnerSucceeds(t *testing.T) {
	withFakeServiceRunner(t, nil)

	if got := checkSSHDRunning(); got.Status != CheckOK {
		t.Fatalf("status = %v, want CheckOK", got.Status)
	}
}

// TestCheckSSHDRunning_FailWhenAllProbesFail asserts that when every service
// probe fails, the check reports sshd not running.
func TestCheckSSHDRunning_FailWhenAllProbesFail(t *testing.T) {
	withFakeServiceRunner(t, func(string, []string) error { return errors.New("down") })

	if got := checkSSHDRunning(); got.Status != CheckFail {
		t.Fatalf("status = %v, want CheckFail", got.Status)
	}
}

// TestReloadSSHD_SucceedsThroughRunner exercises the service-restart path with a
// succeeding fake runner — its first no-root test.
func TestReloadSSHD_SucceedsThroughRunner(t *testing.T) {
	calls := withFakeServiceRunner(t, nil)

	if err := reloadSSHD(); err != nil {
		t.Fatalf("reloadSSHD: %v", err)
	}
	if len(*calls) == 0 {
		t.Fatal("reloadSSHD did not go through the runner")
	}
}

// TestReloadSSHD_ReturnsRunnerError asserts that when the reload command fails on
// every attempt, reloadSSHD propagates the error.
func TestReloadSSHD_ReturnsRunnerError(t *testing.T) {
	withFakeServiceRunner(t, func(string, []string) error { return errors.New("reload failed") })

	if err := reloadSSHD(); err == nil {
		t.Fatal("reloadSSHD should return the runner error when all attempts fail")
	}
}
