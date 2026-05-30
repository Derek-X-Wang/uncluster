package validate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeCheck returns a CheckRunner that yields a fixed result for the "doctor"
// check, optionally embedding a Caller token in the raw output to prove
// redaction reaches evidence.
func fakeCheck(state string, raw string) CheckRunner {
	return func(name string) CheckResult {
		return CheckResult{Name: name, State: state, Raw: raw}
	}
}

func newTestRunner(t *testing.T, r *Runner) *Runner {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	r.EvidenceRoot = filepath.Join(root, "uncluster-validate")
	r.BreadcrumbPath = filepath.Join(state, "uncluster", "validation.jsonl")
	r.Commit = func() (string, bool) { return "abc1234", true }
	if r.Tier == "" {
		r.Tier = "local"
	}
	if r.Target == "" {
		r.Target = "this-machine"
	}
	if len(r.Checks) == 0 {
		r.Checks = []string{"doctor"}
	}
	if r.Safety == "" {
		r.Safety = SafetyInspect
	}
	return r
}

func TestRun_HealthyHostPassesAndWritesEvidence(t *testing.T) {
	r := newTestRunner(t, &Runner{
		Check: fakeCheck("ok", `{"checks":[{"component":"sshd","check":"installed","state":"ok"}],"exit_code":0,"summary":{"ok":1,"warn":0,"fail":0}}`),
	})

	res, err := r.Run()
	if err != nil {
		t.Fatalf("Run() returned error on healthy host: %v", err)
	}
	if !res.Passed {
		t.Errorf("healthy host: Passed = false, want true")
	}
	if res.ExitCode != 0 {
		t.Errorf("healthy host: ExitCode = %d, want 0", res.ExitCode)
	}

	// Evidence dir must exist, be 0700, and contain the manifest + check output.
	info, err := os.Stat(res.EvidencePath)
	if err != nil {
		t.Fatalf("evidence dir not created: %v", err)
	}
	// Unix mode bits only — Windows reports 0777 for dirs regardless of the
	// requested mode (it uses ACLs, not POSIX permissions). The 0700 intent is
	// still asserted on Unix where it is the real access control; on Windows we
	// just confirm the dir exists. Mirrors config_resolve_test.go's guard.
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Errorf("evidence dir mode = %#o, want 0700", perm)
		}
	}
	for _, f := range []string{"manifest.json", "summary.json"} {
		if _, err := os.Stat(filepath.Join(res.EvidencePath, f)); err != nil {
			t.Errorf("expected evidence file %s: %v", f, err)
		}
	}
}

func TestRun_UnhealthyHostFails(t *testing.T) {
	r := newTestRunner(t, &Runner{
		Check: fakeCheck("fail", `{"checks":[{"component":"sshd","check":"running","state":"fail"}],"exit_code":2,"summary":{"ok":0,"warn":0,"fail":1}}`),
	})
	res, err := r.Run()
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if res.Passed {
		t.Errorf("unhealthy host: Passed = true, want false")
	}
	if res.ExitCode == 0 {
		t.Errorf("unhealthy host: ExitCode = 0, want non-zero")
	}
}

// TestRun_EvidenceRedactsCallerToken is the load-bearing security acceptance:
// a Caller token in check output must never land in evidence on disk.
func TestRun_EvidenceRedactsCallerToken(t *testing.T) {
	const callerTok = "uct_caller_idididididididi_secretsecretsecretsecretsecretsecretsecretsecret00"
	r := newTestRunner(t, &Runner{
		Check: fakeCheck("ok", "doctor ran with Authorization: Bearer "+callerTok),
	})
	res, err := r.Run()
	if err != nil {
		t.Fatalf("Run(): %v", err)
	}
	// Walk every file in the evidence dir and assert the token is absent.
	err = filepath.Walk(res.EvidencePath, func(p string, fi os.FileInfo, e error) error {
		if e != nil || fi.IsDir() {
			return e
		}
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), callerTok) {
			t.Errorf("evidence file %s contains the plaintext caller token", p)
		}
		if strings.Contains(string(b), "secretsecretsecret") {
			t.Errorf("evidence file %s contains the token secret", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRun_BreadcrumbAppendedOutsideRepo(t *testing.T) {
	r := newTestRunner(t, &Runner{
		Check: fakeCheck("ok", "{}"),
	})
	res, err := r.Run()
	if err != nil {
		t.Fatalf("Run(): %v", err)
	}

	b, err := os.ReadFile(r.BreadcrumbPath)
	if err != nil {
		t.Fatalf("breadcrumb not written at %s: %v", r.BreadcrumbPath, err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly 1 breadcrumb line, got %d", len(lines))
	}
	var bc map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &bc); err != nil {
		t.Fatalf("breadcrumb line is not valid JSON: %v\n%s", err, lines[0])
	}
	for _, k := range []string{"ts", "commit", "dirty", "tier", "target", "checks", "result", "evidence_path"} {
		if _, ok := bc[k]; !ok {
			t.Errorf("breadcrumb missing key %q: %s", k, lines[0])
		}
	}
	if bc["commit"] != "abc1234" {
		t.Errorf("breadcrumb commit = %v, want abc1234", bc["commit"])
	}
	if bc["dirty"] != true {
		t.Errorf("breadcrumb dirty = %v, want true", bc["dirty"])
	}
	if bc["evidence_path"] != res.EvidencePath {
		t.Errorf("breadcrumb evidence_path = %v, want %s", bc["evidence_path"], res.EvidencePath)
	}

	// A second run appends a second line (the breadcrumb is a durable log).
	if _, err := r.Run(); err != nil {
		t.Fatalf("second Run(): %v", err)
	}
	b2, _ := os.ReadFile(r.BreadcrumbPath)
	if n := len(strings.Split(strings.TrimSpace(string(b2)), "\n")); n != 2 {
		t.Errorf("after 2 runs expected 2 breadcrumb lines, got %d", n)
	}
}

// TestRun_RefusesPrivilegedWithoutFlag asserts the safety gate refuses before
// doing ANY work (no evidence dir, no breadcrumb, the check never runs).
func TestRun_RefusesPrivilegedWithoutFlag(t *testing.T) {
	checkRan := false
	r := newTestRunner(t, &Runner{
		Safety: SafetyPrivileged,
		Check: func(name string) CheckResult {
			checkRan = true
			return CheckResult{Name: name, State: "ok"}
		},
	})
	_, err := r.Run()
	if err == nil {
		t.Fatal("Run() with privileged + no --allow-mutate should refuse")
	}
	if !strings.Contains(err.Error(), "--allow-mutate") {
		t.Errorf("refusal error = %v, want it to mention --allow-mutate", err)
	}
	if checkRan {
		t.Error("the check ran despite the safety refusal — must make no changes")
	}
	if _, err := os.Stat(r.BreadcrumbPath); err == nil {
		t.Error("breadcrumb was written despite the safety refusal")
	}
}
