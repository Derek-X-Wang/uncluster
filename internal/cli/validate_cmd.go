package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/agent"
	"github.com/derek-x-wang/uncluster/internal/gatekeeper"
	"github.com/derek-x-wang/uncluster/internal/validate"
)

// newValidateCmd wires the ADR-0009 `validate` surface. It ORCHESTRATES the
// repo-owned health checks (it does not define "healthy" — that's
// `agent doctor --json`), captures redacted /tmp evidence, leaves a durable
// breadcrumb, and enforces the safety-class refusal matrix. The `validate`
// skill is a thin wrapper over this command; CI and dogfood call it too.
func newValidateCmd() *cobra.Command {
	var (
		tier        string
		target      string
		checks      []string
		safety      string
		allowMutate bool
		allowReboot bool
		evidenceRt  string
	)
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Run repo-owned validation checks, capture evidence, leave a breadcrumb (ADR-0009)",
		Long: `Orchestrates the repo-owned health checks (it does NOT define "healthy" —
` + "`uncluster agent doctor --json`" + ` does), writes ephemeral evidence to
/tmp/uncluster-validate/<run-id>/ (mode 0700, Caller tokens redacted), appends a
one-line breadcrumb to ~/.local/state/uncluster/validation.jsonl, and prints a
terse verdict.

Safety classes (Axis 2): inspect (read-only) and bounded run freely; privileged
requires --allow-mutate; disruptive requires --allow-reboot. The auto-invoke
hook only ever runs --safety inspect.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sc, err := validate.ParseSafetyClass(safety)
			if err != nil {
				return err
			}
			if evidenceRt == "" {
				evidenceRt = validate.DefaultEvidenceRoot()
			}
			bcPath, err := validate.DefaultBreadcrumbPath()
			if err != nil {
				return err
			}

			r := &validate.Runner{
				Tier:           tier,
				Target:         target,
				Checks:         checks,
				Safety:         sc,
				AllowMutate:    allowMutate,
				AllowReboot:    allowReboot,
				EvidenceRoot:   evidenceRt,
				BreadcrumbPath: bcPath,
				Commit:         gitCommitDirty,
				Check:          makeCheckRunner(cmd.Context()),
			}

			res, err := r.Run()
			if err != nil {
				// Safety refusal or an evidence/breadcrumb write failure. Surface
				// it plainly; no verdict line (nothing ran on a refusal).
				return err
			}

			// Terse verdict naming the evidence dir (acceptance: verdict names
			// the path).
			verb := "PASS"
			if !res.Passed {
				verb = "FAIL"
			}
			var states []string
			for _, c := range res.Checks {
				states = append(states, fmt.Sprintf("%s=%s", c.Name, c.State))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "validate %s  [%s/%s %s]  %s\n",
				verb, tier, target, sc, strings.Join(states, " "))
			fmt.Fprintf(cmd.OutOrStdout(), "evidence: %s\n", res.EvidencePath)

			if !res.Passed {
				return &exitCodeError{code: res.ExitCode}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&tier, "tier", "local", "where/who runs it: local|dogfood")
	cmd.Flags().StringVar(&target, "target", "this-machine", "target: this-machine|<agent>")
	cmd.Flags().StringSliceVar(&checks, "checks", []string{"doctor"}, "checks to run (comma-separated)")
	cmd.Flags().StringVar(&safety, "safety", "inspect", "safety class: inspect|bounded|privileged|disruptive")
	cmd.Flags().BoolVar(&allowMutate, "allow-mutate", false, "authorize privileged (sudo) checks")
	cmd.Flags().BoolVar(&allowReboot, "allow-reboot", false, "authorize disruptive (reboot/self-update) checks")
	cmd.Flags().StringVar(&evidenceRt, "evidence-root", "", "override evidence root (default /tmp/uncluster-validate)")
	return cmd
}

// makeCheckRunner returns the production CheckRunner. The "doctor" check runs
// the repo-owned doctor IN-PROCESS (reusing gatekeeper.Doctor + the same
// prepended checks `agent doctor --json` uses) and captures the JSON as
// evidence — so validate and doctor share ONE health definition. Unknown check
// names return a fail so a typo doesn't silently pass.
func makeCheckRunner(ctx context.Context) validate.CheckRunner {
	return func(name string) validate.CheckResult {
		switch name {
		case "doctor":
			return runDoctorCheck(ctx)
		case "bounded-fixture":
			// The #108 bounded-class fixture: writes only to a throwaway temp
			// scope and self-cleans (zero residue), exercising the mutating-
			// guardrail machinery (lock + snapshot/restore) on a harmless
			// target. Reach it with: validate --checks bounded-fixture
			// --safety bounded.
			return validate.RunBoundedFixture(validate.BoundedFixtureOpts{})
		case "install-smoke":
			// The #109 privileged install-smoke: snapshot the install footprint,
			// run the REAL `agent install`, verify via doctor --json, restore on
			// failure. Requires --safety privileged --allow-mutate (enforced by
			// the Runner). The real-machine exercise is deferred to a
			// ready-for-human slice; the orchestration is the shippable unit.
			return runInstallSmokeCheck(ctx)
		default:
			return validate.CheckResult{
				Name:  name,
				State: "fail",
				Raw:   fmt.Sprintf("unknown check %q (wired checks: doctor, bounded-fixture, install-smoke)", name),
			}
		}
	}
}

// runDoctorCheck executes the repo-owned doctor and shapes it as a CheckResult.
// State is derived from the doctor exit code (0=ok → "ok", 1=warn → "warn",
// 2=fail → "fail"); Raw is the doctor --json blob (redacted on write).
func runDoctorCheck(ctx context.Context) validate.CheckResult {
	cfgPath, err := agent.ResolveConfigPath()
	if err != nil {
		return validate.CheckResult{Name: "doctor", State: "fail", Raw: "resolve config path: " + err.Error()}
	}
	cfg, err := agent.LoadConfig(cfgPath)
	if err != nil {
		return validate.CheckResult{Name: "doctor", State: "fail", Raw: "load agent config: " + err.Error()}
	}
	results := append(
		gatekeeper.DoctorResults{
			gatekeeper.CheckConfigLoadedPath(cfgPath),
			gatekeeper.CheckUpdateHostAllowlist(cfg.AllowedUpdateHosts()),
		},
		gatekeeper.Doctor(ctx, cfg)...,
	)
	var buf bytes.Buffer
	_ = writeDoctorJSON(&buf, results, results.ExitCode())

	state := "ok"
	switch results.ExitCode() {
	case 1:
		state = "warn"
	case 2:
		state = "fail"
	}
	return validate.CheckResult{Name: "doctor", State: state, Raw: buf.String()}
}

// runInstallSmokeCheck wires the REAL install + doctor-verify into the #109
// install-smoke orchestration. The footprint is the ADR-0004 install surface
// (CA pubkey, sshd drop-in, principals dir, system agent.toml). Install runs the
// real `gatekeeper.Install`; Verify runs doctor in-process and is healthy only
// when doctor reports zero failing checks. The snapshot/restore + lock are owned
// by validate.RunInstallSmoke / the Runner.
//
// This is the production path; it only fires under `--safety privileged
// --allow-mutate`. Running it on the operator's own box performs a real install
// — that real-machine exercise is the deferred ready-for-human slice, not part
// of AFK CI.
func runInstallSmokeCheck(ctx context.Context) validate.CheckResult {
	cfgPath, err := agent.ResolveConfigPath()
	if err != nil {
		return validate.CheckResult{Name: "install-smoke", State: "fail", Raw: "resolve config path: " + err.Error()}
	}
	cfg, err := agent.LoadConfig(cfgPath)
	if err != nil {
		return validate.CheckResult{Name: "install-smoke", State: "fail", Raw: "load agent config: " + err.Error()}
	}
	exe, err := os.Executable()
	if err != nil {
		return validate.CheckResult{Name: "install-smoke", State: "fail", Raw: "resolve executable: " + err.Error()}
	}

	footprint := []string{
		cfg.ExpectedPaths.CAPubkey,
		cfg.ExpectedPaths.SSHDropIn,
		cfg.ExpectedPaths.PrincipalsDir,
		agent.SystemConfigPath(),
	}

	return validate.RunInstallSmoke(validate.InstallSmokeOpts{
		Footprint: footprint,
		Install: func() error {
			return gatekeeper.Install(ctx, cfg, exe)
		},
		Verify: func() (bool, string) {
			results := append(
				gatekeeper.DoctorResults{
					gatekeeper.CheckConfigLoadedPath(cfgPath),
					gatekeeper.CheckUpdateHostAllowlist(cfg.AllowedUpdateHosts()),
				},
				gatekeeper.Doctor(ctx, cfg)...,
			)
			var buf bytes.Buffer
			_ = writeDoctorJSON(&buf, results, results.ExitCode())
			// Healthy only when doctor has zero failing checks (exit code != 2).
			// A warn (exit 1) is tolerated, matching the CI --no-fails gate.
			return results.ExitCode() != 2, buf.String()
		},
	})
}

// gitCommitDirty returns the current repo commit (short) and whether the tree
// is dirty, for the breadcrumb. Best-effort: returns ("unknown", false) when
// not in a git repo (e.g. validating from an installed binary outside a
// checkout) so validate still works — the breadcrumb just records "unknown".
func gitCommitDirty() (string, bool) {
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "unknown", false
	}
	commit := strings.TrimSpace(string(out))
	st, err := exec.Command("git", "status", "--porcelain").Output()
	if err != nil {
		return commit, false
	}
	dirty := len(bytes.TrimSpace(st)) > 0
	return commit, dirty
}
