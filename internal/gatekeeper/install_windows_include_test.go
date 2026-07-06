//go:build windows

package gatekeeper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSSHDConfigHasInclude covers the pure detection of an existing
// drop-in Include directive in a Windows base sshd_config. Win32-OpenSSH's
// stock config ships with NO Include, so the gatekeeper must detect its
// absence reliably and avoid double-appending on re-install (#126).
func TestSSHDConfigHasInclude(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "stock win32-openssh config has no include",
			content: "# strictly stock\nPasswordAuthentication yes\nSubsystem sftp sftp-server.exe\n",
			want:    false,
		},
		{
			name:    "explicit backslash include for the drop-in dir",
			content: "Include __PROGRAMDATA__\\ssh\\sshd_config.d\\*\n",
			want:    true,
		},
		{
			name:    "explicit forward-slash include for the drop-in dir",
			content: "Include __PROGRAMDATA__/ssh/sshd_config.d/*\n",
			want:    true,
		},
		{
			name:    "include with no glob suffix still counts",
			content: "Include C:\\ProgramData\\ssh\\sshd_config.d\n",
			want:    true,
		},
		{
			name:    "include is case-insensitive on the directive keyword",
			content: "include sshd_config.d/*\n",
			want:    true,
		},
		{
			name:    "commented-out include does not count",
			content: "# Include sshd_config.d/*\n",
			want:    false,
		},
		{
			name:    "include of an unrelated file does not count",
			content: "Include C:\\ProgramData\\ssh\\some_other.conf\n",
			want:    false,
		},
		{
			name:    "our own marker append is detected",
			content: "PasswordAuthentication yes\n# Added by uncluster agent install\nInclude __PROGRAMDATA__\\ssh\\sshd_config.d\\*\n",
			want:    true,
		},
		{
			// #177: an Include AFTER a Match block is scoped to that block, so it
			// does NOT make the drop-in global — must not count as covering.
			name:    "include after a Match block is not global",
			content: "PasswordAuthentication yes\nMatch Group administrators\n       AuthorizedKeysFile x\nInclude __PROGRAMDATA__/ssh/sshd_config.d/*\n",
			want:    false,
		},
		{
			name:    "include before a Match block is global",
			content: "Include __PROGRAMDATA__/ssh/sshd_config.d/*\nMatch Group administrators\n       AuthorizedKeysFile x\n",
			want:    true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sshdConfigHasDropInInclude(tt.content); got != tt.want {
				t.Errorf("sshdConfigHasDropInInclude(%q) = %v, want %v", tt.content, got, tt.want)
			}
		})
	}
}

// TestEnsureWindowsIncludeAt covers the read/append behaviour against a fake
// config path. It must append the Include (with marker) when missing, be
// idempotent on re-run, and leave an already-covered config untouched.
func TestEnsureWindowsIncludeAt(t *testing.T) {
	t.Run("appends_include_when_missing", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "sshd_config")
		const stock = "# stock win32-openssh\nPasswordAuthentication yes\n"
		if err := os.WriteFile(cfg, []byte(stock), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := ensureWindowsIncludeAt(cfg); err != nil {
			t.Fatalf("ensureWindowsIncludeAt: %v", err)
		}
		b, err := os.ReadFile(cfg)
		if err != nil {
			t.Fatal(err)
		}
		got := string(b)
		if !strings.Contains(got, "# Added by uncluster agent install") {
			t.Errorf("expected marker comment, got:\n%s", got)
		}
		if !sshdConfigHasDropInInclude(got) {
			t.Errorf("config still lacks a drop-in Include after append:\n%s", got)
		}
		// Stock content must be preserved.
		if !strings.Contains(got, "PasswordAuthentication yes") {
			t.Errorf("original content lost:\n%s", got)
		}
	})

	t.Run("idempotent_no_double_append", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "sshd_config")
		if err := os.WriteFile(cfg, []byte("PasswordAuthentication yes\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := ensureWindowsIncludeAt(cfg); err != nil {
			t.Fatalf("first ensureWindowsIncludeAt: %v", err)
		}
		first, _ := os.ReadFile(cfg)
		if err := ensureWindowsIncludeAt(cfg); err != nil {
			t.Fatalf("second ensureWindowsIncludeAt: %v", err)
		}
		second, _ := os.ReadFile(cfg)
		if string(first) != string(second) {
			t.Errorf("re-run mutated the file (double append?):\nfirst:\n%s\nsecond:\n%s", first, second)
		}
		// Exactly one Include line.
		if n := strings.Count(string(second), "sshd_config.d"); n != 1 {
			t.Errorf("expected exactly one drop-in Include reference, got %d:\n%s", n, second)
		}
	})

	t.Run("no_change_when_already_covered", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "sshd_config")
		const covered = "Include __PROGRAMDATA__\\ssh\\sshd_config.d\\*\nPasswordAuthentication yes\n"
		if err := os.WriteFile(cfg, []byte(covered), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := ensureWindowsIncludeAt(cfg); err != nil {
			t.Fatalf("ensureWindowsIncludeAt: %v", err)
		}
		b, _ := os.ReadFile(cfg)
		if string(b) != covered {
			t.Errorf("covered config was modified:\nwant:\n%s\ngot:\n%s", covered, b)
		}
		if strings.Contains(string(b), "# Added by uncluster agent install") {
			t.Errorf("marker added to an already-covered config:\n%s", b)
		}
	})

	t.Run("missing_base_config_is_not_an_error", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "does_not_exist")
		if err := ensureWindowsIncludeAt(cfg); err != nil {
			t.Errorf("missing base config should be tolerated, got: %v", err)
		}
	})

	// #177: the stock Win32-OpenSSH config ends with `Match Group administrators`.
	// The Include MUST be inserted before that block so CA trust + principals apply
	// to non-admin connections (appending at EOF scoped them to admins only).
	t.Run("inserts_before_trailing_Match_block", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "sshd_config")
		const stock = "PasswordAuthentication yes\nSubsystem sftp sftp-server.exe\n\n" +
			"Match Group administrators\n" +
			"       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\n"
		if err := os.WriteFile(cfg, []byte(stock), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := ensureWindowsIncludeAt(cfg); err != nil {
			t.Fatalf("ensureWindowsIncludeAt: %v", err)
		}
		s := readFileString(t, cfg)
		inc := strings.Index(s, "sshd_config.d")
		mat := strings.Index(s, "Match Group administrators")
		if inc < 0 || mat < 0 || inc > mat {
			t.Errorf("Include must be placed before the Match block (inc=%d, mat=%d):\n%s", inc, mat, s)
		}
		if !sshdConfigHasDropInInclude(s) {
			t.Errorf("global (pre-Match) include not detected after insert:\n%s", s)
		}
		if !strings.Contains(s, "administrators_authorized_keys") {
			t.Errorf("Match block content lost:\n%s", s)
		}
	})

	t.Run("self_heals_post_Match_include", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "sshd_config")
		// The old buggy state: Include appended AFTER the Match block.
		const buggy = "PasswordAuthentication yes\n" +
			"Match Group administrators\n       AuthorizedKeysFile x\n\n" +
			"# Added by uncluster agent install\n" +
			"Include __PROGRAMDATA__/ssh/sshd_config.d/*\n"
		if err := os.WriteFile(cfg, []byte(buggy), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := ensureWindowsIncludeAt(cfg); err != nil {
			t.Fatalf("ensureWindowsIncludeAt: %v", err)
		}
		s := readFileString(t, cfg)
		if !sshdConfigHasDropInInclude(s) {
			t.Errorf("did not self-heal to a global include:\n%s", s)
		}
		if inc, mat := strings.Index(s, "sshd_config.d"), strings.Index(s, "Match Group administrators"); inc > mat {
			t.Errorf("first include still after the Match block (inc=%d, mat=%d):\n%s", inc, mat, s)
		}
		// A healed config is now idempotent.
		if err := ensureWindowsIncludeAt(cfg); err != nil {
			t.Fatalf("second ensureWindowsIncludeAt: %v", err)
		}
		if again := readFileString(t, cfg); again != s {
			t.Errorf("second run mutated a healed config:\nfirst:\n%s\nsecond:\n%s", s, again)
		}
	})
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
