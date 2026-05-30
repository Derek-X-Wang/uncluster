// Package validate is the repo-owned implementation of the ADR-0009 `validate`
// surface: it orchestrates the existing repo-owned health checks (it does NOT
// define "healthy" — `uncluster agent doctor --json` does), captures ephemeral
// evidence under /tmp with Caller tokens redacted, leaves a durable non-repo
// breadcrumb, and enforces the safety-class refusal matrix.
//
// CI, the `validate` skill, and the dogfood harness all call this one package
// so there is no second definition to drift (ADR-0009 "one source of truth").
package validate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CheckResult is the outcome of running one named check. Raw is the check's
// full output (e.g. the `doctor --json` blob) captured into evidence; it is
// redacted before it ever touches disk.
type CheckResult struct {
	Name  string `json:"name"`
	State string `json:"state"` // "ok" | "warn" | "fail"
	Raw   string `json:"-"`     // captured to a per-check evidence file, not the manifest
}

// CheckRunner runs a single named check and returns its result. In production
// the "doctor" check execs `uncluster agent doctor --json`; tests inject a fake
// so the orchestration is unit-testable without a live host.
type CheckRunner func(name string) CheckResult

// Runner holds one validate invocation's configuration. The Evidence/Breadcrumb
// paths and Commit/Check funcs are injectable so the orchestration is testable
// with fakes (no real /tmp pollution, no real git, no real doctor binary).
type Runner struct {
	Tier   string   // "local" | "dogfood"
	Target string   // "this-machine" | <agent>
	Checks []string // e.g. ["doctor"]
	Safety SafetyClass

	AllowMutate bool
	AllowReboot bool

	// EvidenceRoot is the parent dir for per-run evidence dirs (default
	// /tmp/uncluster-validate). BreadcrumbPath is the durable jsonl log
	// (default ~/.local/state/uncluster/validation.jsonl).
	EvidenceRoot   string
	BreadcrumbPath string

	// Check runs a single check (injectable). Commit returns the current repo
	// commit + dirty flag for the breadcrumb (injectable).
	Check  CheckRunner
	Commit func() (commit string, dirty bool)

	// Now is injectable for deterministic timestamps in tests.
	Now func() time.Time
}

// Result is what Run reports back to the CLI for the in-conversation verdict.
type Result struct {
	Passed       bool
	ExitCode     int
	EvidencePath string
	Checks       []CheckResult
}

// manifest is the per-run manifest.json: the inputs + per-check states. Raw
// outputs go to separate per-check files (redacted); the manifest itself never
// embeds Raw.
type manifest struct {
	RunID     string        `json:"run_id"`
	StartedAt string        `json:"started_at"`
	Tier      string        `json:"tier"`
	Target    string        `json:"target"`
	Safety    string        `json:"safety"`
	Commit    string        `json:"commit"`
	Dirty     bool          `json:"dirty"`
	Checks    []CheckResult `json:"checks"`
	Passed    bool          `json:"passed"`
}

// breadcrumb is the one-line-per-run durable record (ADR-0009 decision 2). Kept
// outside the repo so "was this validated at commit X?" survives the ephemeral
// evidence.
type breadcrumb struct {
	TS           int64    `json:"ts"`
	Commit       string   `json:"commit"`
	Dirty        bool     `json:"dirty"`
	Tier         string   `json:"tier"`
	Target       string   `json:"target"`
	Checks       []string `json:"checks"`
	Result       string   `json:"result"` // "pass" | "fail"
	EvidencePath string   `json:"evidence_path"`
}

// Run executes the validate invocation: enforce the safety gate FIRST (refuse
// before any work), run each check, write redacted evidence (0700), append the
// breadcrumb, and return a verdict. A refusal returns an error and makes no
// changes (no evidence dir, no breadcrumb, no check run).
func (r *Runner) Run() (Result, error) {
	if err := CheckSafetyAllowed(r.Safety, r.AllowMutate, r.AllowReboot); err != nil {
		return Result{}, err
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	started := now()
	runID := newRunID(started)

	commit, dirty := "", false
	if r.Commit != nil {
		commit, dirty = r.Commit()
	}

	// Run checks.
	results := make([]CheckResult, 0, len(r.Checks))
	passed := true
	for _, name := range r.Checks {
		cr := r.Check(name)
		results = append(results, cr)
		if cr.State == "fail" {
			passed = false
		}
	}

	evidenceRoot := r.EvidenceRoot
	if evidenceRoot == "" {
		evidenceRoot = filepath.Join(os.TempDir(), "uncluster-validate")
	}
	evidenceDir := filepath.Join(evidenceRoot, runID)

	if err := r.writeEvidence(evidenceDir, manifest{
		RunID:     runID,
		StartedAt: started.UTC().Format(time.RFC3339),
		Tier:      r.Tier,
		Target:    r.Target,
		Safety:    string(r.Safety),
		Commit:    commit,
		Dirty:     dirty,
		Checks:    results,
		Passed:    passed,
	}, results); err != nil {
		return Result{}, fmt.Errorf("write evidence: %w", err)
	}

	resultWord := "pass"
	if !passed {
		resultWord = "fail"
	}
	if err := r.appendBreadcrumb(breadcrumb{
		TS:           started.Unix(),
		Commit:       commit,
		Dirty:        dirty,
		Tier:         r.Tier,
		Target:       r.Target,
		Checks:       r.Checks,
		Result:       resultWord,
		EvidencePath: evidenceDir,
	}); err != nil {
		return Result{}, fmt.Errorf("append breadcrumb: %w", err)
	}

	exit := 0
	if !passed {
		exit = 1
	}
	return Result{Passed: passed, ExitCode: exit, EvidencePath: evidenceDir, Checks: results}, nil
}

// writeEvidence creates the per-run evidence dir (0700) and writes the manifest,
// a summary, and one redacted file per check's raw output. EVERYTHING written
// passes through RedactSecrets so a Caller token can never land on disk.
func (r *Runner) writeEvidence(dir string, m manifest, results []CheckResult) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Defensively re-assert the mode in case a permissive umask widened it.
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}

	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := writeRedacted(filepath.Join(dir, "manifest.json"), mb); err != nil {
		return err
	}

	// summary.json: a terse pass/state rollup separate from the full manifest.
	summary := map[string]any{
		"run_id": m.RunID,
		"passed": m.Passed,
		"checks": func() []map[string]string {
			out := make([]map[string]string, 0, len(results))
			for _, c := range results {
				out = append(out, map[string]string{"name": c.Name, "state": c.State})
			}
			return out
		}(),
	}
	sb, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	if err := writeRedacted(filepath.Join(dir, "summary.json"), sb); err != nil {
		return err
	}

	// One redacted file per check holding its raw output (the doctor json,
	// command logs, etc.). This is where token-bearing content would otherwise
	// leak, so redaction is mandatory.
	for _, c := range results {
		if c.Raw == "" {
			continue
		}
		fn := filepath.Join(dir, "check-"+sanitizeName(c.Name)+".out")
		if err := writeRedacted(fn, []byte(c.Raw)); err != nil {
			return err
		}
	}
	return nil
}

// appendBreadcrumb appends one JSON line to the durable breadcrumb log, creating
// the parent dir if needed. The breadcrumb carries no raw output, but redaction
// is applied to the marshaled line as belt-and-suspenders.
func (r *Runner) appendBreadcrumb(bc breadcrumb) error {
	path := r.BreadcrumbPath
	if path == "" {
		var err error
		path, err = DefaultBreadcrumbPath()
		if err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	line, err := json.Marshal(bc)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(RedactSecrets(string(line)) + "\n")
	return err
}

// writeRedacted writes content to path with mode 0600, redacting secrets first.
func writeRedacted(path string, content []byte) error {
	return os.WriteFile(path, []byte(RedactSecrets(string(content))), 0o600)
}

// newRunID builds a sortable, unique per-run id: <RFC3339-ish timestamp>-<rand>.
func newRunID(t time.Time) string {
	return fmt.Sprintf("%s-%s", t.UTC().Format("20060102T150405Z"), randHex(4))
}

// sanitizeName makes a check name safe as a filename component.
func sanitizeName(s string) string {
	b := []byte(s)
	for i := range b {
		c := b[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			b[i] = '_'
		}
	}
	return string(b)
}

// DefaultBreadcrumbPath returns ~/.local/state/uncluster/validation.jsonl
// (XDG_STATE_HOME-aware), the durable non-repo location from ADR-0009.
func DefaultBreadcrumbPath() (string, error) {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "uncluster", "validation.jsonl"), nil
}

// DefaultEvidenceRoot returns /tmp/uncluster-validate (ADR-0009).
func DefaultEvidenceRoot() string {
	return filepath.Join(os.TempDir(), "uncluster-validate")
}
