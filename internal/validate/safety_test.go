package validate

import (
	"strings"
	"testing"
)

// TestCheckSafetyAllowed covers the safety-class refusal matrix (#106,
// ADR-0009 Axis 2). `inspect` is read-only and always allowed. `bounded`
// writes only to throwaway scopes and self-cleans — allowed without an extra
// flag. `privileged` (sudo: real install, account creation) requires explicit
// --allow-mutate. `disruptive` (reboot, self-update, deprovision) requires
// explicit --allow-reboot. Auto-sudo/auto-reboot on every commit would brick
// the operator's dev machine, so the gate must refuse by default.
func TestCheckSafetyAllowed(t *testing.T) {
	cases := []struct {
		name        string
		class       SafetyClass
		allowMutate bool
		allowReboot bool
		wantErr     bool
		errContains string
	}{
		{name: "inspect always allowed", class: SafetyInspect, wantErr: false},
		{name: "bounded allowed without flags", class: SafetyBounded, wantErr: false},

		{name: "privileged refused without flag", class: SafetyPrivileged, wantErr: true, errContains: "--allow-mutate"},
		{name: "privileged allowed with --allow-mutate", class: SafetyPrivileged, allowMutate: true, wantErr: false},
		{name: "privileged not unlocked by --allow-reboot", class: SafetyPrivileged, allowReboot: true, wantErr: true, errContains: "--allow-mutate"},

		{name: "disruptive refused without flag", class: SafetyDisruptive, wantErr: true, errContains: "--allow-reboot"},
		{name: "disruptive allowed with --allow-reboot", class: SafetyDisruptive, allowReboot: true, wantErr: false},
		{name: "disruptive not unlocked by --allow-mutate", class: SafetyDisruptive, allowMutate: true, wantErr: true, errContains: "--allow-reboot"},

		{name: "unknown class refused", class: SafetyClass("nonsense"), wantErr: true, errContains: "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckSafetyAllowed(tc.class, tc.allowMutate, tc.allowReboot)
			if tc.wantErr && err == nil {
				t.Fatalf("CheckSafetyAllowed(%q, mutate=%v, reboot=%v) = nil, want error",
					tc.class, tc.allowMutate, tc.allowReboot)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("CheckSafetyAllowed(%q, ...) = %v, want nil", tc.class, err)
			}
			if tc.errContains != "" && (err == nil || !strings.Contains(err.Error(), tc.errContains)) {
				t.Errorf("error = %v, want it to mention %q", err, tc.errContains)
			}
		})
	}
}

// TestParseSafetyClass verifies string → SafetyClass parsing with rejection of
// garbage (so a typo can't silently downgrade the gate).
func TestParseSafetyClass(t *testing.T) {
	for _, ok := range []string{"inspect", "bounded", "privileged", "disruptive"} {
		if _, err := ParseSafetyClass(ok); err != nil {
			t.Errorf("ParseSafetyClass(%q) errored: %v", ok, err)
		}
	}
	if _, err := ParseSafetyClass("INSPECT"); err != nil {
		t.Errorf("ParseSafetyClass should be case-insensitive, got %v", err)
	}
	if _, err := ParseSafetyClass("dangerous"); err == nil {
		t.Errorf("ParseSafetyClass(%q) should reject an unknown class", "dangerous")
	}
}
