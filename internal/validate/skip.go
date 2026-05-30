package validate

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// SkipQuery is the current invocation's identity, matched against prior
// breadcrumbs to decide whether validation can be skipped (#113).
type SkipQuery struct {
	Commit string
	Dirty  bool
	Tier   string
	Target string
	Checks []string
}

// ReadBreadcrumbs reads the durable breadcrumb log (validation.jsonl), one JSON
// object per line. Unparseable lines are SKIPPED (fail-safe — a corrupt line
// must not crash or wedge the reader). A missing file is not an error and
// yields no entries (the caller then re-runs). Returned in file order.
func ReadBreadcrumbs(path string) ([]breadcrumb, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open breadcrumb log %s: %w", path, err)
	}
	defer f.Close()

	var out []breadcrumb
	sc := bufio.NewScanner(f)
	// Breadcrumb lines are small, but allow a generous line size in case an
	// evidence path is long.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var bc breadcrumb
		if json.Unmarshal([]byte(line), &bc) != nil {
			continue // corrupt line — skip, never fail the whole read
		}
		out = append(out, bc)
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("scan breadcrumb log: %w", err)
	}
	return out, nil
}

// ShouldSkip reports whether the current invocation can be skipped because an
// identical run already PASSED. Skip iff some prior breadcrumb matches on
// commit + dirty(==false) + tier + target + checks(order-independent) AND was a
// pass. Invalidation (never skip): a dirty current tree; a differing
// commit/tier/target/checks; a prior recorded on a dirty tree; no matching
// pass. Fail-safe by construction — anything short of a clean, exact,
// passing match re-runs.
//
// When multiple breadcrumbs match the identity, the LATEST (highest TS) verdict
// wins, so a re-validation that later passed overrides an earlier fail.
func ShouldSkip(prior []breadcrumb, q SkipQuery) (bool, string) {
	// A dirty working tree is never skippable — the code under validation isn't
	// the committed code, so no prior PASS describes it.
	if q.Dirty {
		return false, "working tree is dirty — always re-validate"
	}

	wantChecks := normalizedChecks(q.Checks)

	// Find the most recent matching breadcrumb for this identity.
	var best *breadcrumb
	for i := range prior {
		bc := prior[i]
		if bc.Dirty {
			continue // a PASS recorded on a dirty tree is not a trustworthy baseline
		}
		if bc.Commit != q.Commit || bc.Tier != q.Tier || bc.Target != q.Target {
			continue
		}
		if normalizedChecks(bc.Checks) != wantChecks {
			continue
		}
		if best == nil || bc.TS >= best.TS {
			b := bc
			best = &b
		}
	}

	if best == nil {
		return false, "no matching prior validation — re-run"
	}
	if best.Result != "pass" {
		return false, fmt.Sprintf("prior validation at %s was a %s — re-run", best.Commit, best.Result)
	}
	return true, fmt.Sprintf("already validated at commit %s (tier=%s target=%s checks=%s) — skipping",
		best.Commit, best.Tier, best.Target, wantChecks)
}

// normalizedChecks returns a stable, order-independent key for a checks set so
// "doctor,install" matches "install,doctor".
func normalizedChecks(checks []string) string {
	cp := append([]string(nil), checks...)
	sort.Strings(cp)
	return strings.Join(cp, ",")
}
