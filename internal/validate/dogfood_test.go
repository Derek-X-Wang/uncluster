package validate

import (
	"strings"
	"testing"
)

// TestClassifyDogfood is the load-bearing #112 truth table: the plain-ssh
// control disambiguates a product failure from a transport/environment one,
// and an absent control yields indeterminate (never a clean product-fail).
// Per ADR-0009 decision 5.
func TestClassifyDogfood(t *testing.T) {
	cases := []struct {
		name              string
		controlConfigured bool
		plainSSHOK        bool
		unclusterSSHOK    bool
		want              DogfoodClass
	}{
		// No plain-ssh control → cannot interpret a dogfood failure.
		{"no control, both fail → indeterminate", false, false, false, DogfoodIndeterminate},
		{"no control, uncluster ok → indeterminate", false, false, true, DogfoodIndeterminate},
		{"no control, plain ok uncluster fail → still indeterminate (control not trusted)", false, true, false, DogfoodIndeterminate},

		// Control configured: the classifier can disambiguate.
		{"plain ok + uncluster ok → pass", true, true, true, DogfoodPass},
		{"plain ok + uncluster FAIL → product", true, true, false, DogfoodProduct},
		{"plain FAIL (neither) → transport", true, false, false, DogfoodTransport},
		{"plain FAIL but uncluster ok → transport (control unreachable; environment-class)", true, false, true, DogfoodTransport},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyDogfood(tc.controlConfigured, tc.plainSSHOK, tc.unclusterSSHOK)
			if got != tc.want {
				t.Errorf("ClassifyDogfood(control=%v, plain=%v, uncluster=%v) = %q, want %q",
					tc.controlConfigured, tc.plainSSHOK, tc.unclusterSSHOK, got, tc.want)
			}
		})
	}
}

// TestRunDogfood_PlainSSHControlRunsFirst asserts the harness ALWAYS runs the
// plain-ssh control before the uncluster-ssh path (without the control, a
// failure is uninterpretable).
func TestRunDogfood_PlainSSHControlRunsFirst(t *testing.T) {
	var order []string
	res := RunDogfood(DogfoodOpts{
		Target:            "windows-rig",
		ControlConfigured: true,
		PlainSSH: func() (bool, string) {
			order = append(order, "plain")
			return true, "plain ssh ok"
		},
		UnclusterSSH: func() (bool, string) {
			order = append(order, "uncluster")
			return true, "uncluster ssh ok: hostname=windows-rig"
		},
	})

	if len(order) < 2 || order[0] != "plain" {
		t.Errorf("plain-ssh control must run first; order = %v", order)
	}
	if res.Class != DogfoodPass {
		t.Errorf("both transports ok → Class = %q, want pass", res.Class)
	}
	if res.State != "ok" {
		t.Errorf("pass class → State = %q, want ok", res.State)
	}
}

// TestRunDogfood_ProductFailure: plain-ssh works, uncluster-ssh doesn't →
// product-class failure, State=fail, evidence names both attempts.
func TestRunDogfood_ProductFailure(t *testing.T) {
	res := RunDogfood(DogfoodOpts{
		Target:            "windows-rig",
		ControlConfigured: true,
		PlainSSH:          func() (bool, string) { return true, "plain ssh reached windows-rig" },
		UnclusterSSH:      func() (bool, string) { return false, "uncluster ssh: 403 no ACL row" },
	})
	if res.Class != DogfoodProduct {
		t.Errorf("Class = %q, want product (plain ok, uncluster fail)", res.Class)
	}
	if res.State != "fail" {
		t.Errorf("product failure → State = %q, want fail", res.State)
	}
	if !strings.Contains(res.Raw, "plain ssh reached") || !strings.Contains(res.Raw, "403 no ACL") {
		t.Errorf("evidence should capture both transport attempts: %s", res.Raw)
	}
}

// TestRunDogfood_TransportFailure: neither transport works → transport-class,
// NOT a clean product failure.
func TestRunDogfood_TransportFailure(t *testing.T) {
	res := RunDogfood(DogfoodOpts{
		Target:            "windows-rig",
		ControlConfigured: true,
		PlainSSH:          func() (bool, string) { return false, "plain ssh: connection refused" },
		UnclusterSSH:      func() (bool, string) { return false, "uncluster ssh: dial timeout" },
	})
	if res.Class != DogfoodTransport {
		t.Errorf("Class = %q, want transport (neither transport works)", res.Class)
	}
	if res.State != "fail" {
		t.Errorf("transport failure → State = %q, want fail", res.State)
	}
}

// TestRunDogfood_IndeterminateWithoutControl: no plain-ssh control configured →
// indeterminate, never a clean product-fail (a dogfood failure is
// uninterpretable without the control).
func TestRunDogfood_IndeterminateWithoutControl(t *testing.T) {
	uncRan := false
	res := RunDogfood(DogfoodOpts{
		Target:            "windows-rig",
		ControlConfigured: false, // no plain-ssh control
		UnclusterSSH: func() (bool, string) {
			uncRan = true
			return false, "uncluster ssh failed"
		},
	})
	if res.Class != DogfoodIndeterminate {
		t.Errorf("Class = %q, want indeterminate (no control configured)", res.Class)
	}
	// The harness may still attempt uncluster-ssh, but the verdict must be
	// indeterminate, and it must NOT be reported as a product failure.
	if res.State == "fail" && res.Class == DogfoodProduct {
		t.Error("a no-control dogfood failure must never be classified product")
	}
	_ = uncRan
	if !strings.Contains(strings.ToLower(res.Raw), "indeterminate") && !strings.Contains(strings.ToLower(res.Raw), "no plain-ssh control") {
		t.Errorf("evidence should explain the indeterminate root cause: %s", res.Raw)
	}
}
