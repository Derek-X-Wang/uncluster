package gatekeeper

import "github.com/derek-x-wang/uncluster/internal/api"

// HealthChecks converts DoctorResults to the wire-shaped api.AgentHealthCheck
// slice. This is the SINGLE definition of the doctor → health mapping (#104,
// ADR-0009 "one source of truth for healthy"): `uncluster agent doctor --json`,
// the agent heartbeat health provider, CI's doctor-parsing asserts, and the
// future validate skill all consume this identical shape. There is no second
// place that builds AgentHealthCheck from a doctor result — that was the drift
// this consolidation removes.
//
// Message inclusion rule: a check's Message is attached when it is the payload
// (Informational checks like config-loaded-path / update-host-allowlist, whose
// OK status alone tells the operator nothing) or when the check is not OK (so a
// warn/fail always explains itself). Plain OK checks suppress their message to
// keep the JSON terse.
func (r DoctorResults) HealthChecks() []api.AgentHealthCheck {
	checks := make([]api.AgentHealthCheck, 0, len(r))
	for _, c := range r {
		hc := api.AgentHealthCheck{
			Component: healthComponent(c.Name),
			Check:     healthCheckField(c.Name),
			State:     healthState(c.Status),
		}
		if c.Message != "" && (c.Informational || c.Status != CheckOK) {
			msg := c.Message
			hc.Message = &msg
		}
		checks = append(checks, hc)
	}
	return checks
}

// healthComponent maps a doctor check name to the heartbeat `component` field.
func healthComponent(name string) string {
	switch name {
	case "sshd-binary", "sshd-installed", "sshd-running", "sshd-drop-in", "sshd-effective-config", "sshd-principals-command-binary", "macos-include":
		return "sshd"
	case "ca-pubkey":
		return "ca_pubkey"
	case "principals-dir", "principals-file-acl", "spool-dir":
		return "principals"
	case "writer-service":
		return "writer_service"
	case "service-account":
		return "service_account"
	case "service-group":
		return "service_group"
	case "service-running", "service-installed":
		return "service"
	case "config-loaded-path", "config-ownership":
		return "config"
	case "update-host-allowlist":
		return "selfupdate"
	default:
		return name
	}
}

// healthCheckField maps a doctor check name to the heartbeat `check` field.
func healthCheckField(name string) string {
	switch name {
	case "sshd-binary", "sshd-installed", "service-installed":
		return "installed"
	case "sshd-running", "service-running":
		return "running"
	case "sshd-drop-in":
		return "config_drop_in"
	case "sshd-effective-config":
		return "effective_config"
	case "sshd-principals-command-binary":
		return "principals_command_binary"
	case "ca-pubkey":
		return "present"
	case "principals-dir":
		return "dir_writable"
	case "principals-file-acl":
		return "file_acl"
	case "spool-dir":
		return "spool_acl"
	case "writer-service":
		return "running"
	case "service-account":
		return "exists"
	case "service-group":
		return "group_exists"
	case "macos-include":
		return "include_directive"
	case "config-loaded-path":
		return "loaded_path"
	case "config-ownership":
		return "ownership"
	case "update-host-allowlist":
		return "host_allowlist"
	default:
		return name
	}
}

// healthState maps a doctor CheckStatus to the heartbeat `state` string.
func healthState(s CheckStatus) string {
	switch s {
	case CheckOK:
		return "ok"
	case CheckWarn:
		return "warn"
	case CheckFail:
		return "fail"
	default:
		return "unknown"
	}
}
