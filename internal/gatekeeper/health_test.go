package gatekeeper

import (
	"encoding/json"
	"testing"
)

// TestDoctorResultsHealthChecks verifies the single conversion from internal
// DoctorResults to the wire-shaped api.AgentHealthCheck slice (#104). This is
// the ONE place the doctor → health-shape mapping lives, so `doctor --json`,
// the heartbeat health provider, CI, and the future validate skill all parse
// the identical shape. Drift between the heartbeat shape and the doctor --json
// shape is exactly what this consolidation kills.
func TestDoctorResultsHealthChecks(t *testing.T) {
	results := DoctorResults{
		CheckConfigLoadedPath("/etc/uncluster/agent.toml"),
		CheckUpdateHostAllowlist([]string{"github.com"}),
		{Name: "sshd-binary", Status: CheckOK, Message: "sshd found"},
		{Name: "principals-dir", Status: CheckFail, Message: "owner derek (want root)"},
		{Name: "config-ownership", Status: CheckWarn, Message: "absent"},
	}

	checks := results.HealthChecks()
	if len(checks) != len(results) {
		t.Fatalf("HealthChecks() len = %d, want %d", len(checks), len(results))
	}

	// config-loaded-path → component=config check=loaded_path; informational,
	// so its message must survive even though state=ok.
	if checks[0].Component != "config" || checks[0].Check != "loaded_path" || checks[0].State != "ok" {
		t.Errorf("config-loaded-path mapped to %+v, want component=config check=loaded_path state=ok", checks[0])
	}
	if checks[0].Message == nil || *checks[0].Message != "/etc/uncluster/agent.toml" {
		t.Errorf("config-loaded-path message = %v, want the path (informational payload must survive)", checks[0].Message)
	}

	// update-host-allowlist informational message survives too.
	if checks[1].Component != "selfupdate" || checks[1].Message == nil {
		t.Errorf("update-host-allowlist mapped to %+v, want component=selfupdate with message", checks[1])
	}

	// Non-informational OK check (sshd-binary) suppresses its message.
	if checks[2].State != "ok" || checks[2].Message != nil {
		t.Errorf("sshd-binary mapped to %+v, want state=ok, message suppressed", checks[2])
	}

	// Fail check carries its message regardless of informational flag.
	if checks[3].Component != "principals" || checks[3].Check != "dir_writable" || checks[3].State != "fail" {
		t.Errorf("principals-dir mapped to %+v, want component=principals check=dir_writable state=fail", checks[3])
	}
	if checks[3].Message == nil || *checks[3].Message != "owner derek (want root)" {
		t.Errorf("principals-dir fail message = %v, want it preserved", checks[3].Message)
	}

	// config-ownership is a new check (#104) — must map to a stable component.
	if checks[4].Component != "config" || checks[4].Check != "ownership" || checks[4].State != "warn" {
		t.Errorf("config-ownership mapped to %+v, want component=config check=ownership state=warn", checks[4])
	}

	// The whole slice must be JSON-marshalable (doctor --json round-trip).
	b, err := json.Marshal(checks)
	if err != nil {
		t.Fatalf("marshal health checks: %v", err)
	}
	var back []map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal health checks: %v", err)
	}
	if _, ok := back[0]["component"]; !ok {
		t.Errorf("marshaled JSON missing 'component' key: %s", b)
	}
}
