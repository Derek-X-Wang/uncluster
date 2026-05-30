package validate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// query is the current invocation's identity, matched against prior breadcrumbs.
func mkQuery() SkipQuery {
	return SkipQuery{
		Commit: "abc1234",
		Dirty:  false,
		Tier:   "local",
		Target: "this-machine",
		Checks: []string{"doctor"},
	}
}

// TestShouldSkip_MatchingPriorPass: a prior PASS at the same commit (clean
// tree, same tier/target/checks) → skip (#113).
func TestShouldSkip_MatchingPriorPass(t *testing.T) {
	prior := []breadcrumb{
		{Commit: "abc1234", Dirty: false, Tier: "local", Target: "this-machine", Checks: []string{"doctor"}, Result: "pass"},
	}
	skip, reason := ShouldSkip(prior, mkQuery())
	if !skip {
		t.Errorf("matching prior PASS should skip; reason=%q", reason)
	}
	if !strings.Contains(strings.ToLower(reason), "already validated") {
		t.Errorf("skip reason should say 'already validated', got %q", reason)
	}
}

// TestShouldSkip_DirtyTreeNeverSkips: a dirty working tree must NEVER skip,
// even with a matching prior PASS.
func TestShouldSkip_DirtyTreeNeverSkips(t *testing.T) {
	prior := []breadcrumb{
		{Commit: "abc1234", Dirty: false, Tier: "local", Target: "this-machine", Checks: []string{"doctor"}, Result: "pass"},
	}
	q := mkQuery()
	q.Dirty = true
	if skip, _ := ShouldSkip(prior, q); skip {
		t.Error("dirty working tree must never skip")
	}
}

// TestShouldSkip_PriorWasDirtyDoesNotCount: a prior PASS that was recorded with
// dirty=true is not a trustworthy baseline → don't skip.
func TestShouldSkip_PriorWasDirtyDoesNotCount(t *testing.T) {
	prior := []breadcrumb{
		{Commit: "abc1234", Dirty: true, Tier: "local", Target: "this-machine", Checks: []string{"doctor"}, Result: "pass"},
	}
	if skip, _ := ShouldSkip(prior, mkQuery()); skip {
		t.Error("a prior PASS recorded on a dirty tree must not justify a skip")
	}
}

func TestShouldSkip_DifferingFieldsReRun(t *testing.T) {
	base := breadcrumb{Commit: "abc1234", Dirty: false, Tier: "local", Target: "this-machine", Checks: []string{"doctor"}, Result: "pass"}
	cases := []struct {
		name string
		mut  func(b *breadcrumb)
	}{
		{"different commit", func(b *breadcrumb) { b.Commit = "deadbeef" }},
		{"different tier", func(b *breadcrumb) { b.Tier = "dogfood" }},
		{"different target", func(b *breadcrumb) { b.Target = "windows-rig" }},
		{"different checks", func(b *breadcrumb) { b.Checks = []string{"doctor", "install-smoke"} }},
		{"prior was a FAIL", func(b *breadcrumb) { b.Result = "fail" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := base
			tc.mut(&b)
			if skip, _ := ShouldSkip([]breadcrumb{b}, mkQuery()); skip {
				t.Errorf("%s should NOT skip", tc.name)
			}
		})
	}
}

// TestShouldSkip_ChecksOrderIndependent: the checks set should match regardless
// of order (doctor,install == install,doctor).
func TestShouldSkip_ChecksOrderIndependent(t *testing.T) {
	prior := []breadcrumb{
		{Commit: "abc1234", Dirty: false, Tier: "local", Target: "this-machine", Checks: []string{"install-smoke", "doctor"}, Result: "pass"},
	}
	q := mkQuery()
	q.Checks = []string{"doctor", "install-smoke"}
	if skip, _ := ShouldSkip(prior, q); !skip {
		t.Error("checks should match order-independently")
	}
}

// TestShouldSkip_NoBreadcrumbsReRun: empty history → re-run (nothing to skip).
func TestShouldSkip_NoBreadcrumbsReRun(t *testing.T) {
	if skip, _ := ShouldSkip(nil, mkQuery()); skip {
		t.Error("no breadcrumbs should not skip")
	}
}

// TestShouldSkip_LatestMatchingWins: when multiple breadcrumbs exist, a later
// matching PASS still skips even if an earlier entry for the same commit was a
// FAIL (the most recent verdict for the identity is what counts).
func TestShouldSkip_LatestMatchingWins(t *testing.T) {
	prior := []breadcrumb{
		{Commit: "abc1234", Dirty: false, Tier: "local", Target: "this-machine", Checks: []string{"doctor"}, Result: "fail", TS: 100},
		{Commit: "abc1234", Dirty: false, Tier: "local", Target: "this-machine", Checks: []string{"doctor"}, Result: "pass", TS: 200},
	}
	if skip, _ := ShouldSkip(prior, mkQuery()); !skip {
		t.Error("a later matching PASS should justify a skip")
	}
}

// TestReadBreadcrumbs_ParsesAndTolaratesCorruptLines reads the jsonl log and
// skips unparseable lines (fail-safe: a corrupt line must not crash or wedge).
func TestReadBreadcrumbs_ParsesAndToleratesCorruptLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "validation.jsonl")
	content := `{"ts":1,"commit":"abc1234","dirty":false,"tier":"local","target":"this-machine","checks":["doctor"],"result":"pass","evidence_path":"/x"}
this is not json
{"ts":2,"commit":"deadbeef","dirty":true,"tier":"local","target":"this-machine","checks":["doctor"],"result":"fail","evidence_path":"/y"}
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	bcs, err := ReadBreadcrumbs(path)
	if err != nil {
		t.Fatalf("ReadBreadcrumbs: %v", err)
	}
	if len(bcs) != 2 {
		t.Fatalf("got %d breadcrumbs, want 2 (corrupt line skipped)", len(bcs))
	}
	if bcs[0].Commit != "abc1234" || bcs[1].Commit != "deadbeef" {
		t.Errorf("parsed commits wrong: %+v", bcs)
	}
}

// TestReadBreadcrumbs_MissingFileReRun: a missing breadcrumb file is not an
// error and yields no entries → caller re-runs (fail-safe).
func TestReadBreadcrumbs_MissingFileReRun(t *testing.T) {
	bcs, err := ReadBreadcrumbs(filepath.Join(t.TempDir(), "nope.jsonl"))
	if err != nil {
		t.Errorf("missing breadcrumb file should not error: %v", err)
	}
	if len(bcs) != 0 {
		t.Errorf("missing file should yield 0 breadcrumbs, got %d", len(bcs))
	}
}
