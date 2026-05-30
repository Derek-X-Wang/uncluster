package cli

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/gatekeeper"
)

// TestWriteDoctorJSON verifies the documented `agent doctor --json` schema
// (#104): a top-level object with `checks` (the wire-shaped health array),
// `exit_code` (0=ok/1=warn/2=fail), and a per-state `summary`. CI and the
// future validate skill parse this exact shape, so the keys and the rollup
// must be stable.
func TestWriteDoctorJSON(t *testing.T) {
	results := gatekeeper.DoctorResults{
		gatekeeper.CheckConfigLoadedPath("/etc/uncluster/agent.toml"),
		{Name: "sshd-binary", Status: gatekeeper.CheckOK},
		{Name: "principals-dir", Status: gatekeeper.CheckFail, Message: "owner derek (want root)"},
		{Name: "config-ownership", Status: gatekeeper.CheckWarn, Message: "absent"},
	}
	code := results.ExitCode() // fail present → 2

	var buf bytes.Buffer
	if err := writeDoctorJSON(&buf, results, code); err != nil {
		t.Fatalf("writeDoctorJSON: %v", err)
	}

	var got doctorJSON
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}

	if got.ExitCode != 2 {
		t.Errorf("exit_code = %d, want 2 (a fail check is present)", got.ExitCode)
	}
	if len(got.Checks) != 4 {
		t.Fatalf("checks len = %d, want 4", len(got.Checks))
	}
	if got.Summary.OK != 2 || got.Summary.Warn != 1 || got.Summary.Fail != 1 {
		t.Errorf("summary = %+v, want {OK:2 Warn:1 Fail:1}", got.Summary)
	}

	// The principals-dir fail must surface its message so a CI/skill consumer
	// can show WHY it failed.
	var principals *string
	for _, c := range got.Checks {
		if c.Component == "principals" {
			principals = c.Message
		}
	}
	if principals == nil || *principals != "owner derek (want root)" {
		t.Errorf("principals fail message = %v, want it preserved in JSON", principals)
	}

	// Raw-key assertion: CI's jq parses these literal keys.
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(buf.Bytes(), &raw)
	for _, k := range []string{"checks", "exit_code", "summary"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("doctor --json missing top-level key %q (CI jq depends on it)", k)
		}
	}
}
