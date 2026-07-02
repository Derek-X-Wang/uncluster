package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// TestRelTime verifies the "just now" / "Ns ago" / "Nm ago" / ISO rendering.
func TestRelTime(t *testing.T) {
	cases := []struct {
		dur  time.Duration
		want string // exact prefix match
	}{
		{5 * time.Second, "just now"},
		{29 * time.Second, "just now"},
		{30 * time.Second, "30s ago"},
		{59 * time.Second, "59s ago"},
		{60 * time.Second, "1m ago"},
		{90 * time.Second, "1m ago"},
		{59 * time.Minute, "59m ago"},
		// >1h: should be an ISO timestamp (RFC3339 format).
	}

	for _, tc := range cases {
		got := relTime(tc.dur)
		if got != tc.want {
			t.Errorf("relTime(%v) = %q, want %q", tc.dur, got, tc.want)
		}
	}

	// >1h: just check it's an ISO timestamp (contains 'T' and timezone).
	isoResult := relTime(2 * time.Hour)
	if len(isoResult) < 20 || isoResult[4] != '-' {
		t.Errorf("relTime(2h) = %q, want RFC3339 timestamp", isoResult)
	}
}

// TestParseDurationToSeconds verifies duration parsing.
func TestParseDurationToSeconds(t *testing.T) {
	cases := []struct {
		s    string
		want int64
	}{
		{"3600", 3600},
		{"3600s", 3600},
		{"1h", 3600},
		{"30m", 1800},
		{"1h30m", 5400},
	}
	for _, tc := range cases {
		got, err := parseDurationToSeconds(tc.s)
		if err != nil {
			t.Errorf("parseDurationToSeconds(%q): %v", tc.s, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseDurationToSeconds(%q) = %d, want %d", tc.s, got, tc.want)
		}
	}

	// Invalid inputs.
	if _, err := parseDurationToSeconds("xyz"); err == nil {
		t.Error("parseDurationToSeconds(xyz) should error")
	}
}

// TestRelTime_ISOBeyondHour verifies that durations >1h produce a parseable
// RFC3339 timestamp.
func TestRelTime_ISOBeyondHour(t *testing.T) {
	before := time.Now()
	result := relTime(2 * time.Hour)
	if _, err := time.Parse(time.RFC3339, result); err != nil {
		t.Errorf("relTime(2h) = %q, not RFC3339: %v", result, err)
	}
	// The timestamp should be ~2h before now.
	parsed, _ := time.Parse(time.RFC3339, result)
	diff := before.Sub(parsed) - 2*time.Hour
	if diff < 0 {
		diff = -diff
	}
	if diff > 5*time.Second {
		t.Errorf("relTime(2h) timestamp off by %v", diff)
	}
}

// TestRunAgentsList_StatusAndFilters exercises status computation (with an
// injected now), best-endpoint bias by caller subnet, and the status/subnet
// filters — all through the in-memory client.
func TestRunAgentsList_StatusAndFilters(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	online := now.Add(-5 * time.Second).Unix()
	stale := now.Add(-5 * time.Minute).Unix()

	f := newFakeControlPlaneClient()
	f.addAgent(api.AgentDetail{
		ID: "ag_1", Name: "box-online", AgentVersion: "v2.0.0", LastSeenAt: &online,
		Endpoints: []api.AgentEndpointSummary{
			{Subnet: "home-lan", Address: "192.168.1.5"},
			{Subnet: "home-tailnet", Address: "100.64.0.7"},
		},
	})
	f.addAgent(api.AgentDetail{
		ID: "ag_2", Name: "box-stale", LastSeenAt: &stale,
		Endpoints: []api.AgentEndpointSummary{{Subnet: "home-lan", Address: "192.168.1.9"}},
	})
	f.addAgent(api.AgentDetail{ID: "ag_3", Name: "box-offline"}) // nil LastSeenAt → offline

	// No filters, caller declares home-tailnet → online row shows the tailnet endpoint.
	var out bytes.Buffer
	if err := runAgentsList(context.Background(), f, &out, []string{"home-tailnet"}, now, false, "", ""); err != nil {
		t.Fatalf("runAgentsList: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "box-online") || !strings.Contains(s, "online") || !strings.Contains(s, "100.64.0.7") {
		t.Errorf("online row missing or wrong endpoint:\n%s", s)
	}
	if !strings.Contains(s, "box-stale") || !strings.Contains(s, "stale") {
		t.Errorf("stale row missing:\n%s", s)
	}
	if !strings.Contains(s, "box-offline") || !strings.Contains(s, "offline") {
		t.Errorf("offline row missing:\n%s", s)
	}

	// status=online filter drops stale + offline.
	out.Reset()
	if err := runAgentsList(context.Background(), f, &out, nil, now, false, "", "online"); err != nil {
		t.Fatalf("runAgentsList(status): %v", err)
	}
	s = out.String()
	if !strings.Contains(s, "box-online") || strings.Contains(s, "box-stale") || strings.Contains(s, "box-offline") {
		t.Errorf("status=online filter wrong:\n%s", s)
	}

	// subnet=home-tailnet keeps only the agent advertising it.
	out.Reset()
	if err := runAgentsList(context.Background(), f, &out, nil, now, false, "home-tailnet", ""); err != nil {
		t.Fatalf("runAgentsList(subnet): %v", err)
	}
	s = out.String()
	if !strings.Contains(s, "box-online") || strings.Contains(s, "box-stale") || strings.Contains(s, "box-offline") {
		t.Errorf("subnet=home-tailnet filter wrong:\n%s", s)
	}

	// JSON output renders the raw agent list.
	out.Reset()
	if err := runAgentsList(context.Background(), f, &out, nil, now, true, "", ""); err != nil {
		t.Fatalf("runAgentsList(json): %v", err)
	}
	if !strings.Contains(out.String(), `"id": "ag_1"`) {
		t.Errorf("json output missing agent id:\n%s", out.String())
	}
}

// TestRunAgentsRemove confirms the remove routes through the client and prints
// the confirmation.
func TestRunAgentsRemove(t *testing.T) {
	f := newFakeControlPlaneClient()
	var out bytes.Buffer
	if err := runAgentsRemove(context.Background(), f, &out, "box-a"); err != nil {
		t.Fatalf("runAgentsRemove: %v", err)
	}
	if len(f.removedAgents) != 1 || f.removedAgents[0] != "box-a" {
		t.Fatalf("removedAgents = %v, want [box-a]", f.removedAgents)
	}
	if !strings.Contains(out.String(), "agent box-a revoked") {
		t.Errorf("output = %q, want revoked confirmation", out.String())
	}
}

// TestRunAgentsSet covers set-to-duration, clear (via "0" and via ""), the
// no-change guard, and an invalid duration.
func TestRunAgentsSet(t *testing.T) {
	// Set to 1h → 3600 seconds.
	f := newFakeControlPlaneClient()
	if err := runAgentsSet(context.Background(), f, "box-a", true, "1h"); err != nil {
		t.Fatalf("set 1h: %v", err)
	}
	if len(f.failClosedCalls) != 1 {
		t.Fatalf("calls = %d, want 1", len(f.failClosedCalls))
	}
	if c := f.failClosedCalls[0]; c.IDOrName != "box-a" || c.Seconds == nil || *c.Seconds != 3600 {
		t.Fatalf("call = %+v, want box-a 3600", c)
	}

	// Clear via "0" → nil seconds.
	f = newFakeControlPlaneClient()
	if err := runAgentsSet(context.Background(), f, "box-a", true, "0"); err != nil {
		t.Fatalf(`set "0": %v`, err)
	}
	if len(f.failClosedCalls) != 1 || f.failClosedCalls[0].Seconds != nil {
		t.Fatalf(`clear via "0" = %+v, want nil seconds`, f.failClosedCalls)
	}

	// Clear via "" → nil seconds.
	f = newFakeControlPlaneClient()
	if err := runAgentsSet(context.Background(), f, "box-a", true, ""); err != nil {
		t.Fatalf(`set "": %v`, err)
	}
	if len(f.failClosedCalls) != 1 || f.failClosedCalls[0].Seconds != nil {
		t.Fatalf(`clear via "" = %+v, want nil seconds`, f.failClosedCalls)
	}

	// Flag not changed → error, no client call.
	f = newFakeControlPlaneClient()
	if err := runAgentsSet(context.Background(), f, "box-a", false, ""); err == nil {
		t.Fatal("expected error when no fields changed")
	}
	if len(f.failClosedCalls) != 0 {
		t.Fatalf("no-op should make no call, got %v", f.failClosedCalls)
	}

	// Invalid duration → error.
	f = newFakeControlPlaneClient()
	if err := runAgentsSet(context.Background(), f, "box-a", true, "xyz"); err == nil {
		t.Fatal("expected error on invalid duration")
	}
}
