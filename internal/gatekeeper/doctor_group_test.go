//go:build !windows

package gatekeeper

import (
	"strings"
	"testing"
)

// TestServiceGroupResult covers the pure result-mapping for the macOS/Linux
// service-account GROUP doctor check (#96 acceptance: "doctor reports the
// service account + group as present"). The probe (getent/dscl) is integration-
// only; this exercises the OK/Fail mapping deterministically, mirroring the
// pure-helper test posture of CheckConfigLoadedPath / CheckUpdateHostAllowlist.
func TestServiceGroupResult(t *testing.T) {
	t.Run("ok_when_group_resolves", func(t *testing.T) {
		got := serviceGroupResult("_uncluster")
		if got.Name != "service-group" {
			t.Errorf("Name = %q, want service-group", got.Name)
		}
		if got.Status != CheckOK {
			t.Errorf("Status = %v, want CheckOK", got.Status)
		}
		if !strings.Contains(got.Message, "_uncluster") {
			t.Errorf("Message = %q, want it to name the resolved group", got.Message)
		}
	})

	t.Run("fail_when_group_absent", func(t *testing.T) {
		got := serviceGroupResult("")
		if got.Status != CheckFail {
			t.Errorf("Status with empty group = %v, want CheckFail "+
				"(absent group is the #96 bug that makes config unreadable)", got.Status)
		}
	})
}
