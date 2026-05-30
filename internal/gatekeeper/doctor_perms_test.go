//go:build !windows

package gatekeeper

import (
	"strings"
	"testing"
)

// TestPrincipalsDirResult covers the pure owner/group/mode mapping for the
// principals-dir doctor check (#104). CI asserted owner=root, group=<service
// account>, mode=0775 inline (`assert-principals-dir-perms`); bringing those
// assertions INTO doctor makes doctor the strong source of truth instead of a
// weaker signal than CI. The stat/lookup probe is integration-only; this
// exercises the OK/Fail mapping deterministically, mirroring the pure-helper
// posture of serviceGroupResult.
func TestPrincipalsDirResult(t *testing.T) {
	const dir = "/etc/ssh/auth_principals"

	t.Run("ok_when_owner_group_mode_match", func(t *testing.T) {
		got := principalsDirResult(dir, principalsDirStat{owner: "root", group: "uncluster", mode: 0o775}, "uncluster")
		if got.Name != "principals-dir" {
			t.Errorf("Name = %q, want principals-dir", got.Name)
		}
		if got.Status != CheckOK {
			t.Errorf("Status = %v, want CheckOK (owner/group/mode all correct)", got.Status)
		}
	})

	t.Run("ok_when_darwin_service_account_group", func(t *testing.T) {
		// macOS service account + group are `_uncluster`.
		got := principalsDirResult(dir, principalsDirStat{owner: "root", group: "_uncluster", mode: 0o775}, "_uncluster")
		if got.Status != CheckOK {
			t.Errorf("Status = %v, want CheckOK for darwin _uncluster group", got.Status)
		}
	})

	t.Run("fail_when_owner_not_root", func(t *testing.T) {
		got := principalsDirResult(dir, principalsDirStat{owner: "derek", group: "uncluster", mode: 0o775}, "uncluster")
		if got.Status != CheckFail {
			t.Errorf("Status with non-root owner = %v, want CheckFail", got.Status)
		}
		if !strings.Contains(got.Message, "owner") {
			t.Errorf("Message = %q, want it to mention the owner mismatch", got.Message)
		}
	})

	t.Run("fail_when_group_not_service_account", func(t *testing.T) {
		got := principalsDirResult(dir, principalsDirStat{owner: "root", group: "wheel", mode: 0o775}, "uncluster")
		if got.Status != CheckFail {
			t.Errorf("Status with wrong group = %v, want CheckFail (service account cannot write)", got.Status)
		}
		if !strings.Contains(got.Message, "group") {
			t.Errorf("Message = %q, want it to mention the group mismatch", got.Message)
		}
	})

	t.Run("fail_when_mode_too_narrow", func(t *testing.T) {
		// 0755 strips group-write — the service account cannot write principal
		// files, which is the silent-failure CI's mode assert exists to catch.
		got := principalsDirResult(dir, principalsDirStat{owner: "root", group: "uncluster", mode: 0o755}, "uncluster")
		if got.Status != CheckFail {
			t.Errorf("Status with mode 0755 = %v, want CheckFail (no group write)", got.Status)
		}
		if !strings.Contains(got.Message, "mode") {
			t.Errorf("Message = %q, want it to mention the mode mismatch", got.Message)
		}
	})
}

// TestConfigOwnershipResult covers the pure mapping for the config-ownership
// doctor check (#104). The macOS t2 job asserted `/etc/uncluster/agent.toml`
// is owned root:_uncluster mode 0640 inline (`assert-service-user-and-group`);
// without that ownership the low-priv service account cannot read its config
// and the service fails to start (#96). Bringing it into doctor makes the
// failure legible everywhere doctor runs.
func TestConfigOwnershipResult(t *testing.T) {
	const path = "/etc/uncluster/agent.toml"

	t.Run("ok_when_root_group_0640", func(t *testing.T) {
		got := configOwnershipResult(path, configOwnerStat{owner: "root", group: "uncluster", mode: 0o640}, "uncluster")
		if got.Name != "config-ownership" {
			t.Errorf("Name = %q, want config-ownership", got.Name)
		}
		if got.Status != CheckOK {
			t.Errorf("Status = %v, want CheckOK", got.Status)
		}
	})

	t.Run("fail_when_group_not_service_account", func(t *testing.T) {
		// root:wheel 0640 is the #96 bug: group record absent → chown no-ops →
		// config stays unreadable by the service account.
		got := configOwnershipResult(path, configOwnerStat{owner: "root", group: "wheel", mode: 0o640}, "uncluster")
		if got.Status != CheckFail {
			t.Errorf("Status with group=wheel = %v, want CheckFail (config unreadable by service account)", got.Status)
		}
		if !strings.Contains(got.Message, "group") {
			t.Errorf("Message = %q, want it to mention the group", got.Message)
		}
	})

	t.Run("fail_when_mode_world_readable", func(t *testing.T) {
		// 0644 would world-expose the config (which carries the agent token).
		got := configOwnershipResult(path, configOwnerStat{owner: "root", group: "uncluster", mode: 0o644}, "uncluster")
		if got.Status != CheckFail {
			t.Errorf("Status with mode 0644 = %v, want CheckFail (over-permissive)", got.Status)
		}
		if !strings.Contains(got.Message, "mode") {
			t.Errorf("Message = %q, want it to mention the mode", got.Message)
		}
	})
}
