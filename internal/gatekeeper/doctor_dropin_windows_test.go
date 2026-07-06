//go:build windows

package gatekeeper

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCheckSSHDropInWindows covers the strengthened drop-in check (#177): it
// must FAIL when the base sshd_config Includes the drop-in only AFTER a Match
// block (effectively scoped to admins), even though the drop-in file itself is
// present and correct — the doctor-blindness class this closes.
func TestCheckSSHDropInWindows(t *testing.T) {
	const goodDropIn = "TrustedUserCAKeys C:\\ProgramData\\ssh\\uncluster_ca.pub\n" +
		"AuthorizedPrincipalsFile C:\\ProgramData\\ssh\\auth_principals/%u\n"
	const globalInclude = "Include __PROGRAMDATA__/ssh/sshd_config.d/*\n" +
		"Match Group administrators\n       AuthorizedKeysFile x\n"
	const postMatchInclude = "PasswordAuthentication yes\n" +
		"Match Group administrators\n       AuthorizedKeysFile x\n" +
		"Include __PROGRAMDATA__/ssh/sshd_config.d/*\n"

	write := func(t *testing.T, name, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("missing_drop_in_fails", func(t *testing.T) {
		got := checkSSHDropInWindows(filepath.Join(t.TempDir(), "nope.conf"), write(t, "sshd_config", globalInclude))
		if got.Status != CheckFail {
			t.Errorf("missing drop-in: got %+v, want CheckFail", got)
		}
	})

	t.Run("drop_in_without_directives_warns", func(t *testing.T) {
		got := checkSSHDropInWindows(write(t, "uncluster.conf", "# empty\n"), write(t, "sshd_config", globalInclude))
		if got.Status != CheckWarn {
			t.Errorf("directiveless drop-in: got %+v, want CheckWarn", got)
		}
	})

	t.Run("global_include_ok", func(t *testing.T) {
		got := checkSSHDropInWindows(write(t, "uncluster.conf", goodDropIn), write(t, "sshd_config", globalInclude))
		if got.Status != CheckOK {
			t.Errorf("global include: got %+v, want CheckOK", got)
		}
	})

	t.Run("post_match_include_fails", func(t *testing.T) {
		got := checkSSHDropInWindows(write(t, "uncluster.conf", goodDropIn), write(t, "sshd_config", postMatchInclude))
		if got.Status != CheckFail {
			t.Errorf("post-Match include (scoped to admins) must FAIL, got %+v", got)
		}
	})

	t.Run("missing_base_config_warns", func(t *testing.T) {
		got := checkSSHDropInWindows(write(t, "uncluster.conf", goodDropIn), filepath.Join(t.TempDir(), "no_base"))
		if got.Status != CheckWarn {
			t.Errorf("unreadable base config: got %+v, want CheckWarn", got)
		}
	})
}
