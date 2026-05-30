package validate

import "fmt"

// SafetyClass is ADR-0009 Axis 2: how dangerous a validation is, independent of
// tier. It determines what may run vs what requires explicit authorization.
type SafetyClass string

const (
	// SafetyInspect is read-only (build, plist-lint, `doctor --json`, `sshd -T`,
	// service-status reads). The only class permitted to auto-invoke (the
	// ADR-0009 dev-loop hook, #107).
	SafetyInspect SafetyClass = "inspect"
	// SafetyBounded writes only to throwaway/temp scopes and self-cleans.
	SafetyBounded SafetyClass = "bounded"
	// SafetyPrivileged uses sudo/Administrator: real `agent install`, account/
	// service creation. Manual only — requires explicit --allow-mutate.
	SafetyPrivileged SafetyClass = "privileged"
	// SafetyDisruptive reboots, self-updates, or deprovisions. Manual only —
	// requires explicit --allow-reboot, and is implemented as a two-phase
	// resumable check (#110).
	SafetyDisruptive SafetyClass = "disruptive"
)

// ParseSafetyClass converts a flag string to a SafetyClass, rejecting unknown
// values so a typo cannot silently downgrade the gate. Case-insensitive.
func ParseSafetyClass(s string) (SafetyClass, error) {
	switch SafetyClass(toLowerASCII(s)) {
	case SafetyInspect:
		return SafetyInspect, nil
	case SafetyBounded:
		return SafetyBounded, nil
	case SafetyPrivileged:
		return SafetyPrivileged, nil
	case SafetyDisruptive:
		return SafetyDisruptive, nil
	default:
		return "", fmt.Errorf("unknown safety class %q (want inspect|bounded|privileged|disruptive)", s)
	}
}

// CheckSafetyAllowed enforces the refusal matrix: inspect/bounded run freely;
// privileged requires allowMutate; disruptive requires allowReboot. Returns a
// clear, actionable error when a class is gated and its authorizing flag is
// absent — the caller MUST make no changes when this errors.
//
// Trigger is by safety class, not tier (ADR-0009 decision 1): a hook may
// auto-run inspect, but privileged+disruptive stay explicit manual invocations
// regardless of where they run.
func CheckSafetyAllowed(class SafetyClass, allowMutate, allowReboot bool) error {
	switch class {
	case SafetyInspect, SafetyBounded:
		return nil
	case SafetyPrivileged:
		if !allowMutate {
			return fmt.Errorf("safety class %q requires explicit authorization: pass --allow-mutate (it performs sudo/Administrator mutations: real install, account/service creation)", class)
		}
		return nil
	case SafetyDisruptive:
		if !allowReboot {
			return fmt.Errorf("safety class %q requires explicit authorization: pass --allow-reboot (it reboots / self-updates / deprovisions)", class)
		}
		return nil
	default:
		return fmt.Errorf("unknown safety class %q", class)
	}
}

// toLowerASCII lowercases ASCII letters without importing strings (keeps the
// safety gate dependency-free and trivially auditable).
func toLowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
