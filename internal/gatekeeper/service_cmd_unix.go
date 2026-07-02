//go:build !windows

package gatekeeper

import "os/exec"

// agentServiceName is the single source of truth for the Uncluster Agent's
// service identifier on Unix: the launchd label on macOS and the systemd unit
// name on Linux (both are "com.uncluster.agent"). It was previously string-
// duplicated across install, doctor, restart, and the service definition — the
// same drift class as the once-hardcoded Linux systemd unit name. Windows
// already centralizes its service name; this gives Unix the same fix (#151).
const agentServiceName = "com.uncluster.agent"

// The Gatekeeper probes and reloads system services (systemctl, sshd, and the
// launchctl sshd job) through these package-level runner vars, mirroring the
// launchctl runners in install_launchd_darwin.go. Tests replace them with fakes
// to exercise the service-restart path and doctor's service-status checks
// without root or a real init system (#151). On real machines the defaults
// shell out exactly as before — no behavior change (ADR-0009 tiers unaffected).

// runServiceCmd runs a service command and returns only its error (exit status).
// Used by probes/reloads that care solely whether the command succeeded.
var runServiceCmd = func(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// runServiceCmdOutput runs a service command and returns its stdout, for probes
// that parse the output (e.g. `sshd -T`).
var runServiceCmdOutput = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}
