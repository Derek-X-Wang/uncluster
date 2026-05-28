package agent

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// TestSystemConfigPath_OSShape asserts the platform-specific shape of the
// canonical system path (the install destination chosen for #77).
//
// We don't pin the exact string because PROGRAMDATA on Windows is
// environment-dependent. We assert: (1) the basename is always agent.toml;
// (2) on Unix the prefix is /etc/uncluster; (3) on Windows the suffix is
// the uncluster\agent.toml relative tail.
func TestSystemConfigPath_OSShape(t *testing.T) {
	got := SystemConfigPath()
	if filepath.Base(got) != "agent.toml" {
		t.Errorf("SystemConfigPath basename = %q, want agent.toml", filepath.Base(got))
	}
	switch runtime.GOOS {
	case "windows":
		if !strings.HasSuffix(got, filepath.Join("uncluster", "agent.toml")) {
			t.Errorf("SystemConfigPath on windows = %q, want suffix uncluster\\agent.toml", got)
		}
	default:
		want := "/etc/uncluster/agent.toml"
		if got != want {
			t.Errorf("SystemConfigPath on %s = %q, want %q", runtime.GOOS, got, want)
		}
	}
}

// TestResolveConfigPath_Precedence verifies the service-side resolution
// rules for #77:
//   - When the system-wide file exists, ResolveConfigPath returns it.
//   - When only the per-user file exists, ResolveConfigPath returns that.
//   - When neither exists, ResolveConfigPath still returns the per-user
//     path (the consumer's LoadConfig will fail with a useful error rather
//     than us swallowing it here).
//
// We swap systemConfigPathFn to point at a temp dir so the test can
// stage both files without touching the real /etc or C:\ProgramData.
func TestResolveConfigPath_Precedence(t *testing.T) {
	tmpSys := filepath.Join(t.TempDir(), "system", "agent.toml")
	prevFn := systemConfigPathFn
	systemConfigPathFn = func() string { return tmpSys }
	t.Cleanup(func() { systemConfigPathFn = prevFn })

	// Also redirect the per-user path. The simplest portable override is
	// XDG_CONFIG_HOME — DefaultConfigPath honours it on every platform.
	tmpUser := filepath.Join(t.TempDir(), "user-xdg")
	t.Setenv("XDG_CONFIG_HOME", tmpUser)
	wantUserPath := filepath.Join(tmpUser, "uncluster", "agent.toml")

	t.Run("system_wins_when_both_exist", func(t *testing.T) {
		// Create both files.
		mustWrite(t, tmpSys, "system=1\n")
		mustWrite(t, wantUserPath, "user=1\n")

		got, err := ResolveConfigPath()
		if err != nil {
			t.Fatalf("ResolveConfigPath: %v", err)
		}
		if got != tmpSys {
			t.Errorf("ResolveConfigPath when both exist = %q, want system %q", got, tmpSys)
		}
	})

	t.Run("user_fallback_when_only_user_exists", func(t *testing.T) {
		// Remove the system file.
		_ = os.Remove(tmpSys)
		mustWrite(t, wantUserPath, "user=1\n")

		got, err := ResolveConfigPath()
		if err != nil {
			t.Fatalf("ResolveConfigPath: %v", err)
		}
		if got != wantUserPath {
			t.Errorf("ResolveConfigPath when only user exists = %q, want %q", got, wantUserPath)
		}
	})

	t.Run("returns_user_path_when_neither_exists", func(t *testing.T) {
		_ = os.Remove(tmpSys)
		_ = os.Remove(wantUserPath)

		got, err := ResolveConfigPath()
		if err != nil {
			t.Fatalf("ResolveConfigPath (neither exists): %v", err)
		}
		// We expect the per-user path (LoadConfig will fail with a useful
		// ENOENT for the operator). The function does not synthesise an
		// error here because a missing config is a normal pre-enrollment
		// state.
		if got != wantUserPath {
			t.Errorf("ResolveConfigPath when neither exists = %q, want %q (per-user)", got, wantUserPath)
		}
	})
}

// TestSaveConfigSystem_Idempotent asserts that re-running install on an
// already-installed host (second `agent install`) does not corrupt or
// duplicate the file. We stage the system path under a temp dir and write
// twice; second write must succeed and contain the second config.
//
// Permission-tightening (chown root:uncluster) is skipped here because the
// test runs as a normal user and the chown will not have a target group.
// The restrictSystemConfigACL helper is no-op'd in that case (matches
// production behaviour for first-pass install before the service account
// exists).
func TestSaveConfigSystem_Idempotent(t *testing.T) {
	tmpSys := filepath.Join(t.TempDir(), "system", "agent.toml")
	prevFn := systemConfigPathFn
	systemConfigPathFn = func() string { return tmpSys }
	t.Cleanup(func() { systemConfigPathFn = prevFn })

	cfg1 := Config{Server: "https://a", AgentToken: "tok1"}
	cfg2 := Config{Server: "https://b", AgentToken: "tok2"}

	if err := SaveConfigSystem(tmpSys, cfg1); err != nil {
		t.Fatalf("first SaveConfigSystem: %v", err)
	}
	if err := SaveConfigSystem(tmpSys, cfg2); err != nil {
		t.Fatalf("second SaveConfigSystem (idempotent re-install): %v", err)
	}

	got, err := LoadConfig(tmpSys)
	if err != nil {
		t.Fatalf("LoadConfig after re-install: %v", err)
	}
	// reflect.DeepEqual because Config now contains a []string field
	// (UpdateHostAllowlist, #39) which makes the struct uncomparable
	// with ==. Both sides have nil for that field here.
	if !reflect.DeepEqual(got, cfg2) {
		t.Errorf("re-install did not produce latest content:\n got  %+v\n want %+v", got, cfg2)
	}

	// File mode on Unix should be 0640 (set by SaveConfigSystem). Windows
	// uses ACLs; skip the perm check there.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(tmpSys)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o640 {
			t.Errorf("system config file mode: got %#o want 0640", perm)
		}
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
