package validate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installSmokeFixture builds an InstallSmokeOpts over a temp footprint, with
// injectable install/verify behavior so the orchestration is unit-testable
// WITHOUT a real `sudo agent install` (the real-machine exercise is a deferred
// ready-for-human slice per #109). The fake "install" writes to the footprint
// paths so snapshot/restore has something real to undo.
func installSmokeFixture(t *testing.T) (root string, footprint []string) {
	t.Helper()
	root = t.TempDir()
	footprint = []string{
		filepath.Join(root, "uncluster_ca.pub"),
		filepath.Join(root, "uncluster.conf"),
		filepath.Join(root, "agent.toml"),
	}
	// Pre-existing state: agent.toml already present (a re-install scenario);
	// the others absent (fresh install creates them).
	if err := os.WriteFile(footprint[2], []byte("pre-existing agent.toml\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	return root, footprint
}

func TestInstallSmoke_HappyPath(t *testing.T) {
	_, footprint := installSmokeFixture(t)

	installed := false
	verified := false
	res := RunInstallSmoke(InstallSmokeOpts{
		Footprint: footprint,
		Install: func() error {
			installed = true
			// Simulate a successful install writing the footprint.
			for _, p := range footprint {
				_ = os.WriteFile(p, []byte("installed\n"), 0o640)
			}
			return nil
		},
		Verify: func() (bool, string) {
			verified = true
			return true, `{"checks":[{"component":"sshd","check":"installed","state":"ok"}],"exit_code":0,"summary":{"ok":1,"warn":0,"fail":0}}`
		},
	})

	if !installed {
		t.Error("install fn was not called")
	}
	if !verified {
		t.Error("verify fn was not called")
	}
	if res.State != "ok" {
		t.Errorf("install-smoke State = %q, want ok\nraw: %s", res.State, res.Raw)
	}
	// Evidence (Raw) should carry the doctor json so it lands in evidence.
	if !strings.Contains(res.Raw, "\"state\":\"ok\"") {
		t.Errorf("install-smoke Raw should embed the doctor json verify output, got: %s", res.Raw)
	}
}

func TestInstallSmoke_InjectedInstallFailureRestores(t *testing.T) {
	_, footprint := installSmokeFixture(t)
	// Capture pre-install state for the clean-machine assertion.
	pre := map[string]string{}
	for _, p := range footprint {
		if b, err := os.ReadFile(p); err == nil {
			pre[p] = string(b)
		} else {
			pre[p] = "<absent>"
		}
	}

	res := RunInstallSmoke(InstallSmokeOpts{
		Footprint: footprint,
		Install: func() error {
			// Partially mutate then fail (half-install).
			_ = os.WriteFile(footprint[0], []byte("partial ca\n"), 0o640)
			_ = os.WriteFile(footprint[1], []byte("partial conf\n"), 0o640)
			_ = os.WriteFile(footprint[2], []byte("CLOBBERED\n"), 0o640)
			return os.ErrPermission // injected install failure
		},
		Verify: func() (bool, string) {
			t.Error("verify must NOT run after an install failure")
			return false, ""
		},
	})

	if res.State != "fail" {
		t.Errorf("install-smoke State = %q, want fail on install error", res.State)
	}

	// Restore must have left the machine clean: footprint back to pre-install.
	for _, p := range footprint {
		got := "<absent>"
		if b, err := os.ReadFile(p); err == nil {
			got = string(b)
		}
		if got != pre[p] {
			t.Errorf("footprint %s = %q after restore, want %q (half-install not cleaned)", p, got, pre[p])
		}
	}
}

func TestInstallSmoke_VerifyFailureRestores(t *testing.T) {
	_, footprint := installSmokeFixture(t)
	pre := map[string]string{}
	for _, p := range footprint {
		if b, err := os.ReadFile(p); err == nil {
			pre[p] = string(b)
		} else {
			pre[p] = "<absent>"
		}
	}

	res := RunInstallSmoke(InstallSmokeOpts{
		Footprint: footprint,
		Install: func() error {
			for _, p := range footprint {
				_ = os.WriteFile(p, []byte("installed\n"), 0o640)
			}
			return nil
		},
		Verify: func() (bool, string) {
			// Install "succeeded" but doctor reports a failing check.
			return false, `{"checks":[{"component":"service","check":"running","state":"fail"}],"exit_code":2,"summary":{"ok":0,"warn":0,"fail":1}}`
		},
	})

	if res.State != "fail" {
		t.Errorf("install-smoke State = %q, want fail when doctor verify fails", res.State)
	}
	// A failed verify means the install is not healthy → restore to clean.
	for _, p := range footprint {
		got := "<absent>"
		if b, err := os.ReadFile(p); err == nil {
			got = string(b)
		}
		if got != pre[p] {
			t.Errorf("footprint %s = %q after restore, want %q (unhealthy install not rolled back)", p, got, pre[p])
		}
	}
}

// TestInstallSmoke_NilInstallIsFail guards against a misconfigured invocation:
// without an install fn the check fails clearly rather than no-op-passing.
func TestInstallSmoke_NilInstallIsFail(t *testing.T) {
	_, footprint := installSmokeFixture(t)
	res := RunInstallSmoke(InstallSmokeOpts{Footprint: footprint})
	if res.State != "fail" {
		t.Errorf("install-smoke with nil Install = %q, want fail", res.State)
	}
}
