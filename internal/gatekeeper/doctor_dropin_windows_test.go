//go:build windows

package gatekeeper

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCheckBaseConfigDirectivesWindows covers the #179 doctor check: the CA-trust
// + principals directives must be EFFECTIVE in the base sshd_config (managed
// block present, before the first Match). A block placed after a Match — or
// absent — must FAIL, closing the #175/#177 doctor-blindness class.
func TestCheckBaseConfigDirectivesWindows(t *testing.T) {
	block := managedDirectiveBlock(`C:\ProgramData\ssh\uncluster_ca.pub`, `C:\ProgramData\ssh\auth_principals/%u`)
	const stock = "PasswordAuthentication yes\n" +
		"Match Group administrators\n       AuthorizedKeysFile x\n"

	write := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "sshd_config")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("effective_block_ok", func(t *testing.T) {
		got := checkBaseConfigDirectivesWindows(write(t, upsertManagedBlock(stock, block)))
		if got.Name != "sshd-drop-in" || got.Status != CheckOK {
			t.Errorf("got %+v, want sshd-drop-in CheckOK", got)
		}
	})

	t.Run("no_block_fails", func(t *testing.T) {
		if got := checkBaseConfigDirectivesWindows(write(t, stock)); got.Status != CheckFail {
			t.Errorf("missing block: got %+v, want CheckFail", got)
		}
	})

	t.Run("block_after_match_fails", func(t *testing.T) {
		// Block placed AFTER the Match block is not effective.
		got := checkBaseConfigDirectivesWindows(write(t, stock+block))
		if got.Status != CheckFail {
			t.Errorf("post-Match block: got %+v, want CheckFail", got)
		}
	})

	t.Run("block_without_directives_warns", func(t *testing.T) {
		empty := managedBlockBegin + "\n" + managedBlockEnd + "\n"
		got := checkBaseConfigDirectivesWindows(write(t, empty+stock))
		if got.Status != CheckWarn {
			t.Errorf("directiveless block: got %+v, want CheckWarn", got)
		}
	})

	t.Run("unreadable_base_config_fails", func(t *testing.T) {
		got := checkBaseConfigDirectivesWindows(filepath.Join(t.TempDir(), "nope"))
		if got.Status != CheckFail {
			t.Errorf("missing base config: got %+v, want CheckFail", got)
		}
	})
}
