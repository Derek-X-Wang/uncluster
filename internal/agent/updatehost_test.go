package agent

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestAllowedUpdateHosts_AbsentUsesDefault covers the backwards-compat
// case (#39): an agent.toml that does not mention update_host_allowlist
// must behave as if it was set to the historical default ["github.com"].
// Older installs created before this slice never wrote the field; they
// must keep accepting updates without operator action.
func TestAllowedUpdateHosts_AbsentUsesDefault(t *testing.T) {
	c := Config{
		Server:     "https://x",
		AgentToken: "tok",
		// UpdateHostAllowlist intentionally unset (nil).
	}
	got := c.AllowedUpdateHosts()
	want := []string{"github.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AllowedUpdateHosts (absent) = %v, want %v", got, want)
	}
}

// TestAllowedUpdateHosts_EmptyExplicitDisables covers the operator's
// "no updates" posture (#39): an agent.toml with
// `update_host_allowlist = []` must return empty (not the default), so
// ValidateUpdateURL rejects every URL.
func TestAllowedUpdateHosts_EmptyExplicitDisables(t *testing.T) {
	c := Config{
		Server:              "https://x",
		AgentToken:          "tok",
		UpdateHostAllowlist: []string{}, // explicit empty, NOT nil
	}
	got := c.AllowedUpdateHosts()
	if len(got) != 0 {
		t.Errorf("AllowedUpdateHosts (explicit empty) = %v, want []", got)
	}
}

// TestAllowedUpdateHosts_DefaultNotMutable verifies the package default
// can't be mutated through a Config consumer's returned slice (defensive:
// pre-empts a future caller appending to the slice and corrupting the
// default for the rest of the process).
func TestAllowedUpdateHosts_DefaultNotMutable(t *testing.T) {
	c := Config{Server: "https://x", AgentToken: "tok"}
	got := c.AllowedUpdateHosts()
	got[0] = "evil.example.com"

	// Re-fetch and confirm DefaultUpdateHostAllowlist is unchanged.
	again := c.AllowedUpdateHosts()
	if again[0] != "github.com" {
		t.Errorf("default mutated by caller; got %v, want first elem github.com",
			again)
	}
}

// TestValidateUpdateURL covers the per-acceptance-criterion matrix from
// #39's agent brief. Each subtest names which bullet it covers.
func TestValidateUpdateURL(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		allow    []string
		wantPass bool
	}{
		{
			// "github.com allowlist + github.com URL → accept"
			name:     "exact_match_allows",
			url:      "https://github.com/Derek-X-Wang/uncluster/releases/download/v2.0.1/uncluster-linux-amd64",
			allow:    []string{"github.com"},
			wantPass: true,
		},
		{
			// "github.com allowlist + attacker host → reject"
			name:     "different_host_rejects",
			url:      "https://attacker.example.com/payload",
			allow:    []string{"github.com"},
			wantPass: false,
		},
		{
			// "subdomain handling: github.com allows ONLY github.com"
			name:     "subdomain_rejects",
			url:      "https://evil.github.com/payload",
			allow:    []string{"github.com"},
			wantPass: false,
		},
		{
			// "case-insensitive: Github.Com matches github.com"
			name:     "case_insensitive_allows",
			url:      "https://Github.Com/Derek-X-Wang/uncluster/releases/x",
			allow:    []string{"github.com"},
			wantPass: true,
		},
		{
			// "case-insensitive allowlist entry"
			name:     "allowlist_case_insensitive_allows",
			url:      "https://github.com/x",
			allow:    []string{"GITHUB.COM"},
			wantPass: true,
		},
		{
			// "port preserved: github.com:443 validates against github.com"
			name:     "port_ignored_allows",
			url:      "https://github.com:443/x",
			allow:    []string{"github.com"},
			wantPass: true,
		},
		{
			// "multi-host allowlist accepts either host"
			name:     "multi_host_first_allows",
			url:      "https://github.com/x",
			allow:    []string{"github.com", "releases.uncluster.example.com"},
			wantPass: true,
		},
		{
			name:     "multi_host_second_allows",
			url:      "https://releases.uncluster.example.com/x",
			allow:    []string{"github.com", "releases.uncluster.example.com"},
			wantPass: true,
		},
		{
			// "empty allowlist rejects all"
			name:     "empty_allowlist_rejects",
			url:      "https://github.com/x",
			allow:    []string{},
			wantPass: false,
		},
		{
			// "invalid URL → parse error wrapping ErrDisallowedHost"
			name:     "invalid_url_rejects",
			url:      "://not-a-url",
			allow:    []string{"github.com"},
			wantPass: false,
		},
		{
			// Defensive: opaque URL with no host. Could happen if a
			// compromised Control plane returns e.g. "file:///etc/passwd".
			name:     "no_host_rejects",
			url:      "file:///etc/passwd",
			allow:    []string{"github.com"},
			wantPass: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateUpdateURL(tc.url, tc.allow)
			if tc.wantPass && err != nil {
				t.Errorf("ValidateUpdateURL(%q, %v) = %v, want nil",
					tc.url, tc.allow, err)
			}
			if !tc.wantPass {
				if err == nil {
					t.Errorf("ValidateUpdateURL(%q, %v) = nil, want error",
						tc.url, tc.allow)
				}
				if err != nil && !errors.Is(err, ErrDisallowedHost) {
					t.Errorf("ValidateUpdateURL(%q, %v) = %v, want errors.Is ErrDisallowedHost",
						tc.url, tc.allow, err)
				}
			}
		})
	}
}

// TestValidateUpdateURL_RejectionMessage asserts the rejection log message
// includes both the rejected host and the configured allowlist — this is
// load-bearing for the structured log that the brief calls out (`reason:
// disallowed_host` + visibility of expected vs actual). We assert the
// error string rather than relying on the log call because the log call
// is side-effecting in the agent and noisy to assert in unit tests.
func TestValidateUpdateURL_RejectionMessage(t *testing.T) {
	err := ValidateUpdateURL("https://attacker.example.com/x", []string{"github.com"})
	if err == nil {
		t.Fatal("expected rejection")
	}
	msg := err.Error()
	if !strings.Contains(msg, "attacker.example.com") {
		t.Errorf("error message %q missing rejected host", msg)
	}
	if !strings.Contains(msg, "github.com") {
		t.Errorf("error message %q missing configured allowlist", msg)
	}
}
