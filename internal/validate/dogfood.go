package validate

import (
	"fmt"
	"strings"
)

// DogfoodClass is the product-vs-transport classification of a dogfood run
// (ADR-0009 decision 5). The plain-ssh control disambiguates a real product
// failure from a transport/environment one; without the control a failure is
// uninterpretable.
type DogfoodClass string

const (
	// DogfoodPass: both plain-ssh and uncluster-ssh reached the target.
	DogfoodPass DogfoodClass = "pass"
	// DogfoodProduct: plain-ssh works but uncluster-ssh does not — Uncluster's
	// own SSH brokering is broken (a real product failure).
	DogfoodProduct DogfoodClass = "product"
	// DogfoodTransport: plain-ssh itself does not work — the network/host is the
	// problem, not Uncluster. Environment-class, not a clean product failure.
	DogfoodTransport DogfoodClass = "transport"
	// DogfoodIndeterminate: no plain-ssh control configured, so a dogfood
	// failure's root cause cannot be attributed. Never a clean product-fail.
	DogfoodIndeterminate DogfoodClass = "indeterminate"
)

// ClassifyDogfood is the load-bearing classifier. Truth table:
//   - control not configured        → indeterminate (cannot attribute).
//   - control ok, plain ok, unc ok   → pass.
//   - control ok, plain ok, unc fail → product (uncluster-ssh broken).
//   - control ok, plain fail         → transport (plain ssh can't even reach;
//     uncluster-ssh's result is moot — the environment is the gate).
//
// The plain-ssh control is only trusted when it is configured; an absent
// control yields indeterminate even when plain "succeeds" by accident, because
// without an intentional control there is no reliable baseline.
func ClassifyDogfood(controlConfigured, plainSSHOK, unclusterSSHOK bool) DogfoodClass {
	if !controlConfigured {
		return DogfoodIndeterminate
	}
	if !plainSSHOK {
		// Plain ssh — the baseline — does not work, so the failure is the
		// network/host, not Uncluster's brokering.
		return DogfoodTransport
	}
	// Plain ssh works: now uncluster-ssh is the deciding signal.
	if unclusterSSHOK {
		return DogfoodPass
	}
	return DogfoodProduct
}

// DogfoodOpts configures a dogfood run. The transport probes are injectable so
// the harness + classifier are unit-testable with fakes for each branch — no
// live deployment in CI. In production PlainSSH dials the target with plain
// `ssh` and UnclusterSSH runs `uncluster ssh <target> -- hostname`.
type DogfoodOpts struct {
	Target string
	// ControlConfigured reports whether a plain-ssh control is set up for the
	// target. When false the verdict is indeterminate regardless of probes.
	ControlConfigured bool
	// PlainSSH runs the plain-ssh control and returns (ok, evidence).
	PlainSSH func() (bool, string)
	// UnclusterSSH runs the uncluster-ssh path and returns (ok, evidence).
	UnclusterSSH func() (bool, string)
}

// DogfoodResult is what RunDogfood reports: the classification plus the
// CheckResult-shaped State/Raw so it plugs into the validate CheckRunner via
// CheckResult().
type DogfoodResult struct {
	Class DogfoodClass
	State string
	Raw   string
}

// CheckResult adapts a DogfoodResult to the generic check shape the Runner
// consumes.
func (d DogfoodResult) CheckResult() CheckResult {
	return CheckResult{Name: "dogfood", State: d.State, Raw: d.Raw}
}

// RunDogfood executes a dogfood validation: ALWAYS run the plain-ssh control
// FIRST (so a failure is interpretable), then the uncluster-ssh path, then
// classify. State is "ok" only for a pass; product and transport failures are
// "fail"; indeterminate is "warn" (a failure we cannot attribute is not a clean
// product-fail and should not red-gate the product, but it is not a pass).
func RunDogfood(opts DogfoodOpts) DogfoodResult {
	var log strings.Builder
	fmt.Fprintf(&log, "dogfood target: %s\n", opts.Target)

	// 1. Plain-ssh control FIRST.
	plainOK := false
	if !opts.ControlConfigured {
		log.WriteString("no plain-ssh control configured — a dogfood failure's root cause is INDETERMINATE\n")
	} else if opts.PlainSSH != nil {
		var ev string
		plainOK, ev = opts.PlainSSH()
		fmt.Fprintf(&log, "plain-ssh control: ok=%v — %s\n", plainOK, ev)
	}

	// 2. Uncluster-ssh path (attempted even without a control, for evidence).
	unclusterOK := false
	if opts.UnclusterSSH != nil {
		var ev string
		unclusterOK, ev = opts.UnclusterSSH()
		fmt.Fprintf(&log, "uncluster-ssh path: ok=%v — %s\n", unclusterOK, ev)
	}

	// 3. Classify.
	class := ClassifyDogfood(opts.ControlConfigured, plainOK, unclusterOK)
	fmt.Fprintf(&log, "classification: %s\n", class)

	state := "fail"
	switch class {
	case DogfoodPass:
		state = "ok"
	case DogfoodIndeterminate:
		// Not attributable to the product → warn, not a red product-fail.
		state = "warn"
		log.WriteString("verdict: indeterminate (dogfood transport failed; root cause unknown without a plain-ssh control)\n")
	case DogfoodProduct:
		log.WriteString("verdict: PRODUCT-class failure — plain ssh works but `uncluster ssh` does not (SSH brokering broken)\n")
	case DogfoodTransport:
		log.WriteString("verdict: TRANSPORT/environment-class failure — plain ssh itself does not reach the target\n")
	}

	return DogfoodResult{Class: class, State: state, Raw: log.String()}
}
