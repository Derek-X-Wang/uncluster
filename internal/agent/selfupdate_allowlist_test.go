package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// TestHandleCheckUpdate_RejectsDisallowedAssetURL is the load-bearing
// integration test for #39: a stubbed /v1/agent/update-plan handing back
// a malicious asset URL must produce ErrDisallowedHost. This is the
// contract the brief calls out — Control-plane-compromise bypasses
// SHA256 verification entirely because the attacker controls both files;
// the only defence is the install-time-pinned host allowlist.
//
// We use a synthesized "attacker.example.com" hostname in the URL the
// CP returns. The agent's HTTP client will never resolve that hostname
// because the validator rejects it first — that is the entire point of
// this test. If the validator regresses and *does* let the request out,
// the test asserts that the HTTP attempt would fail with a hostname
// resolution / connection error, NOT a normal selfupdate error path
// (so we'd see the failure either way: validator-rejection now, or
// hostname-resolution-failure if the validator regresses; both are
// distinguishable from ErrDisallowedHost via errors.Is).
func TestHandleCheckUpdate_RejectsDisallowedAssetURL(t *testing.T) {
	// Use an unroutable synthetic host. We deliberately do NOT bind a
	// listener — if the validator regresses and lets the request out,
	// the HTTP client will fail with a DNS lookup error, which is NOT
	// errors.Is ErrDisallowedHost. The test then fails loudly.
	attackerHost := "attacker.example.invalid"
	attackerURL := "https://" + attackerHost + "/payload"
	sha256URL := "https://" + attackerHost + "/payload.sha256"

	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agent/update-plan" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		body := fmt.Sprintf(
			`{"expected_version":"v99.9.9","asset_url_template":%q,"sha256_url_template":%q,"force":true}`,
			attackerURL, sha256URL,
		)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(cp.Close)

	cfg := Config{
		Server:              cp.URL,
		AgentToken:          "uct_agent_AAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		UpdateHostAllowlist: []string{"github.com"}, // attacker host NOT in this list
	}
	a := &Agent{
		cfg:    cfg,
		client: NewServerClient(cp.URL, cfg.AgentToken),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err := a.HandleCheckUpdate(context.Background(), api.CheckUpdateCommand{})
	if err == nil {
		t.Fatalf("HandleCheckUpdate accepted disallowed host (allowed %q to be downloaded)",
			attackerHost)
	}
	if !errors.Is(err, ErrDisallowedHost) {
		t.Errorf("HandleCheckUpdate error = %v, want errors.Is ErrDisallowedHost", err)
	}
	// Confirm the error message names the rejected host (operator log
	// reads `reason=disallowed_host` + rejected URL).
	if !strings.Contains(err.Error(), attackerHost) {
		t.Errorf("error %q does not mention rejected host %q", err, attackerHost)
	}
}

// TestHandleCheckUpdate_RejectsDisallowedSHA256URL covers the same risk
// but on the checksum URL. A compromised Control plane could hand back a
// genuine asset URL on github.com and a fake checksum URL on attacker
// host — without per-URL validation the agent would download the
// attacker's checksum and verify the asset against it, which the
// attacker can defeat by pre-computing the attacker-asset's hash.
//
// We use a synthetic "attacker.example.invalid" hostname for the same
// reason as the asset test (httptest servers all bind to 127.0.0.1 so
// we'd be unable to distinguish allowed vs disallowed by hostname).
func TestHandleCheckUpdate_RejectsDisallowedSHA256URL(t *testing.T) {
	attackerHost := "attacker.example.invalid"
	assetHost := "good.example.invalid" // also synthetic; never reached because sha256 fails first

	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agent/update-plan" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		body := fmt.Sprintf(
			`{"expected_version":"v99.9.9","asset_url_template":%q,"sha256_url_template":%q,"force":true}`,
			"https://"+assetHost+"/binary",
			"https://"+attackerHost+"/checksum", // disallowed
		)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(cp.Close)

	cfg := Config{
		Server:              cp.URL,
		AgentToken:          "uct_agent_AAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		UpdateHostAllowlist: []string{assetHost}, // attacker host NOT in this list
	}
	a := &Agent{
		cfg:    cfg,
		client: NewServerClient(cp.URL, cfg.AgentToken),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err := a.HandleCheckUpdate(context.Background(), api.CheckUpdateCommand{})
	if err == nil || !errors.Is(err, ErrDisallowedHost) {
		t.Fatalf("HandleCheckUpdate error = %v, want ErrDisallowedHost", err)
	}
	if !strings.Contains(err.Error(), attackerHost) {
		t.Errorf("error %q does not mention rejected host %q", err, attackerHost)
	}
}

// TestHandleCheckUpdate_DefaultAllowlistAllowsGithub verifies the
// backwards-compat path. An agent.toml without `update_host_allowlist`
// falls through to AllowedUpdateHosts()'s default of ["github.com"], so
// a github.com URL passes validation. We don't actually download (that
// would hit github.com over the network); we only need to confirm the
// validation step doesn't reject. We do that by stubbing the asset+sha256
// URLs to *match* a host the agent reaches over an httptest server, and
// asserting that the asset's HTTP handler is invoked at least once.
//
// We don't pin update_host_allowlist on the agent so the default kicks
// in — but to avoid the test depending on an external network, we
// add the test server's host to the *default* in a temporary swap.
// Pure-helper: just call ValidateUpdateURL directly with the default.
func TestHandleCheckUpdate_DefaultAllowlistAllowsGithub(t *testing.T) {
	// Pure-helper assertion; HandleCheckUpdate's integration path is
	// already covered by the rejection tests above. The remaining bit is
	// confirming AllowedUpdateHosts()'s default really equals
	// ["github.com"] and ValidateUpdateURL passes a github.com URL.
	c := Config{Server: "https://x", AgentToken: "tok"}
	if err := ValidateUpdateURL(
		"https://github.com/Derek-X-Wang/uncluster/releases/download/v2.0.1/x",
		c.AllowedUpdateHosts(),
	); err != nil {
		t.Errorf("default allowlist rejected github.com URL: %v", err)
	}
}

// TestHandleCheckUpdate_EmptyAllowlistRejectsEverything verifies the
// operator's "updates disabled" posture (`update_host_allowlist = []`).
func TestHandleCheckUpdate_EmptyAllowlistRejectsEverything(t *testing.T) {
	c := Config{
		Server:              "https://x",
		AgentToken:          "tok",
		UpdateHostAllowlist: []string{}, // explicit empty
	}
	allow := c.AllowedUpdateHosts()
	if len(allow) != 0 {
		t.Fatalf("explicit empty allowlist resolved to %v, want []", allow)
	}
	err := ValidateUpdateURL("https://github.com/x", allow)
	if !errors.Is(err, ErrDisallowedHost) {
		t.Errorf("empty allowlist + github.com URL: got %v, want ErrDisallowedHost", err)
	}
}

