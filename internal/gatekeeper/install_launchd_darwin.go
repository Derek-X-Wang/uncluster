//go:build darwin

package gatekeeper

import (
	"context"
	"os/exec"
	"strings"
)

const (
	// launchdAgentLabel is the launchd service identifier for the Uncluster Agent.
	launchdAgentLabel = "com.uncluster.agent"

	// launchdAgentPlist is the on-disk plist path that launchctl bootstrap takes
	// as its argument. Matches serviceUnitPath() for darwin.
	launchdAgentPlist = "/Library/LaunchDaemons/com.uncluster.agent.plist"

	// launchdAgentDomainTarget is the domain-qualified service target used by
	// kickstart and bootout (system/<label>).
	launchdAgentDomainTarget = "system/" + launchdAgentLabel
)

// darwinLaunchctlBootstrap calls `launchctl bootstrap system <plist>`.
// It is a package-level var so unit tests can inject a fake without shelling
// out to launchctl — the same pattern used for usedUIDsDarwin/usedGIDsDarwin.
//
// The real implementation is the default. Tests override to verify idempotency
// and error-propagation logic without root access or a real launchd.
var darwinLaunchctlBootstrap = func(ctx context.Context, plist string) error {
	return exec.CommandContext(ctx, "launchctl", "bootstrap", "system", plist).Run()
}

// darwinLaunchctlKickstart calls `launchctl kickstart -k system/com.uncluster.agent`.
// -k (kill-and-restart) makes it safe to call on an already-running job — it
// stops any running instance and starts a fresh one, giving us idempotent
// restart semantics. Same verb the existing reloadSSHD uses for sshd.
var darwinLaunchctlKickstart = func(ctx context.Context) error {
	return exec.CommandContext(ctx, "launchctl", "kickstart", "-k", launchdAgentDomainTarget).Run()
}

// darwinLaunchctlBootout calls `launchctl bootout system/com.uncluster.agent`.
// Used during stopServiceForReinstall to fully remove the job from the system
// domain before kardianos/service Uninstall removes the plist; without this,
// the domain retains a tombstone reference to the now-deleted plist and a
// subsequent bootstrap on the new plist fails with EEXIST / exit 17.
//
// Errors are intentionally non-fatal at call sites (best-effort) because the
// job may not be in the domain yet (first install that failed mid-way).
var darwinLaunchctlBootout = func(ctx context.Context) error {
	return exec.CommandContext(ctx, "launchctl", "bootout", launchdAgentDomainTarget).Run()
}

// bootstrapServiceDarwin bootstraps the agent plist into the system domain and
// treats "already bootstrapped" (EEXIST / "Bootstrap failed: 17" / "service
// already loaded") as success, matching the isAlreadyInstalledErr idempotency
// posture used for plist installation.
//
// On modern macOS, dropping a plist into /Library/LaunchDaemons does not
// automatically load it into the system domain; an explicit bootstrap call is
// required before any start/kickstart verb can locate the job. The kardianos
// Install() step writes the plist but does NOT bootstrap it, so a bare
// `launchctl start <label>` (or kardianos Start) exits 3 with "Could not find
// service in domain for system" — the exact #99 failure.
func bootstrapServiceDarwin(ctx context.Context) error {
	err := darwinLaunchctlBootstrap(ctx, launchdAgentPlist)
	if err == nil {
		return nil
	}
	if isAlreadyBootstrappedErr(err) {
		return nil // idempotent — already in domain, nothing to do
	}
	return err
}

// isAlreadyBootstrappedErr reports whether the error from `launchctl bootstrap`
// indicates the job is already registered in the target domain (EEXIST case).
// On macOS this surfaces as exit status 17 with the message
// "Bootstrap failed: 17" or "service already loaded".
//
// Intentionally tight: only the EEXIST variants return true. Other failures
// (EPERM "13", ENOENT "2", exit-status-3 "not found") must propagate.
func isAlreadyBootstrappedErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	// "Bootstrap failed: 17" — EEXIST, the canonical already-in-domain error.
	// "service already loaded" — legacy variant seen on some macOS versions.
	// "already bootstrapped" — older launchctl wording.
	return strings.Contains(s, "17") ||
		strings.Contains(s, "already loaded") ||
		strings.Contains(s, "already bootstrapped")
}
