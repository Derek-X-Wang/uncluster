package cli

import (
	"testing"
	"time"
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
