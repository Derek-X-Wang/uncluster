package gatekeeper

import (
	"context"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// FullDoctor is the single, Gatekeeper-owned composition of a doctor run: the
// informational prepend checks followed by the platform Doctor check set. Every
// caller — the heartbeat health provider, the `agent doctor` command, and each
// validate doctor-based check — goes through here, so which checks compose a
// doctor run (and their ordering) can never drift between call sites (#143,
// ADR-0009 "one source of truth for healthy").
//
// The prepends are:
//
//   - config-loaded-path — which agent.toml doctor is reasoning about. Purely
//     informational EXCEPT when configPath is empty, where it warns: that is the
//     one load-bearing prepend, and it is precisely the check the reboot-path
//     callers used to drop by calling bare Doctor.
//   - update-host-allowlist — the self-update host allowlist, informational
//     observability (the Agent enforces it directly in the update flow).
//
// The composition skeleton is identical on both platforms; only Doctor's check
// set differs (doctor_unix.go vs doctor_windows.go). FullDoctor owns the
// skeleton so neither platform re-implements it.
func FullDoctor(ctx context.Context, cfg agent.Config, configPath string) DoctorResults {
	return append(
		DoctorResults{
			CheckConfigLoadedPath(configPath),
			CheckUpdateHostAllowlist(cfg.AllowedUpdateHosts()),
		},
		Doctor(ctx, cfg)...,
	)
}
