package cli

import (
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// equalStrings compares two string slices treating nil and empty as equal.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSplitSSHArgs covers the `--` argument splitting, including the no-`--`
// fallback (acceptance: "Endpoint picking and `--` splitting are unit-tested
// (including the no-`--` fallback)").
func TestSplitSSHArgs(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		wantAgent string
		wantSSH   []string
	}{
		{"agent only", []string{"box"}, "box", nil},
		{"dash then cmd", []string{"box", "--", "whoami"}, "box", []string{"whoami"}},
		{"dash then flags and cmd", []string{"box", "--", "-v", "whoami"}, "box", []string{"-v", "whoami"}},
		{"no dash single (fallback)", []string{"box", "whoami"}, "box", []string{"whoami"}},
		{"no dash multiple (fallback)", []string{"box", "echo", "hi"}, "box", []string{"echo", "hi"}},
		{"trailing dash", []string{"box", "--"}, "box", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotAgent, gotSSH := splitSSHArgs(tc.args)
			if gotAgent != tc.wantAgent {
				t.Errorf("agent = %q, want %q", gotAgent, tc.wantAgent)
			}
			if !equalStrings(gotSSH, tc.wantSSH) {
				t.Errorf("sshArgs = %v, want %v", gotSSH, tc.wantSSH)
			}
		})
	}
}

// TestPickEndpoint covers explicit-subnet priority, caller-subnet overlap, the
// first-endpoint fallback, and the two error paths.
func TestPickEndpoint(t *testing.T) {
	eps := []api.AgentEndpointSummary{
		{Subnet: "home-lan", Address: "192.168.1.5"},
		{Subnet: "home-tailnet", Address: "100.64.0.7"},
	}

	// Explicit --subnet wins over everything.
	if addr, err := pickEndpoint(eps, "home-tailnet", []string{"home-lan"}); err != nil || addr != "100.64.0.7" {
		t.Errorf("explicit subnet = (%q, %v), want (100.64.0.7, nil)", addr, err)
	}

	// Explicit --subnet with no matching endpoint errors.
	if _, err := pickEndpoint(eps, "work-lan", nil); err == nil {
		t.Error("explicit unmatched subnet should error")
	}

	// No explicit subnet: first overlap with caller's declared subnets.
	if addr, err := pickEndpoint(eps, "", []string{"home-tailnet"}); err != nil || addr != "100.64.0.7" {
		t.Errorf("caller-subnet overlap = (%q, %v), want (100.64.0.7, nil)", addr, err)
	}

	// No explicit, no overlap: fall back to first endpoint.
	if addr, err := pickEndpoint(eps, "", nil); err != nil || addr != "192.168.1.5" {
		t.Errorf("fallback = (%q, %v), want (192.168.1.5, nil)", addr, err)
	}

	// No endpoints at all errors.
	if _, err := pickEndpoint(nil, "", nil); err == nil {
		t.Error("no endpoints should error")
	}
}
