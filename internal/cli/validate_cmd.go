package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

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
		force       bool
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

			// Skip-if-already-validated (#113): unless --force, if a prior
			// identical run PASSED at this exact commit on a clean tree, report
			// "already validated" and exit 0 without re-running. Fail-safe — a
			// dirty tree, any differing field, or a missing/corrupt breadcrumb
			// re-runs. This is read-only and never mutates, so it is safe even
			// for privileged/disruptive invocations.
			if !force {
				commit, dirty := gitCommitDirty()
				if bcs, rerr := validate.ReadBreadcrumbs(bcPath); rerr == nil {
					if skip, reason := validate.ShouldSkip(bcs, validate.SkipQuery{
						Commit: commit, Dirty: dirty, Tier: tier, Target: target, Checks: checks,
					}); skip {
						fmt.Fprintf(cmd.OutOrStdout(), "validate SKIP  [%s/%s %s]  %s\n", tier, target, sc, reason)
						fmt.Fprintln(cmd.OutOrStdout(), "(pass --force to re-validate)")
						return nil
					}
				}
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
				Check:          makeCheckRunner(cmd.Context(), allowReboot, target),
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
	cmd.Flags().BoolVar(&force, "force", false, "re-validate even if an identical run already passed at this commit (skip the breadcrumb cache)")
	return cmd
}

// makeCheckRunner returns the production CheckRunner. The "doctor" check runs
// the repo-owned doctor IN-PROCESS (reusing gatekeeper.Doctor + the same
// prepended checks `agent doctor --json` uses) and captures the JSON as
// evidence — so validate and doctor share ONE health definition. Unknown check
// names return a fail so a typo doesn't silently pass.
func makeCheckRunner(ctx context.Context, allowReboot bool, target string) validate.CheckRunner {
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
		case "reboot-survival":
			// The #110 disruptive two-phase reboot-survival check. First run
			// arms (persist state + reboot); the post-reboot re-run resumes and
			// verifies the service resurrected. Requires --safety disruptive
			// --allow-reboot (enforced by the Runner AND the arm phase). The real
			// reboot exercise is deferred to a ready-for-human slice.
			return runRebootSurvivalCheck(ctx, allowReboot)
		case "self-update":
			// The #111 disruptive self-update validation: happy path (agent
			// comes back on the target version) + rollback (a broken update
			// reverts to the prior binary). Requires --safety disruptive
			// --allow-reboot (self-update restarts the service). The
			// orchestration is fully built + unit-tested
			// (validate.RunSelfUpdateValidation); binding it to the REAL
			// download/checksum/atomic-swap against live release artifacts is
			// the deferred ready-for-human real-machine exercise.
			return runSelfUpdateCheck()
		case "dogfood":
			// The #112 dogfood check: validate the target THROUGH Uncluster's
			// own SSH, with a plain-ssh control first to classify failures
			// (product vs transport vs indeterminate). The harness + classifier
			// are fully built + unit-tested (validate.RunDogfood); binding the
			// plain-ssh + `uncluster ssh` probes to a LIVE deployment (CP + 2
			// agents + plain-ssh creds) is the deferred ready-for-human exercise.
			return runDogfoodCheck(target)
		default:
			return validate.CheckResult{
				Name:  name,
				State: "fail",
				Raw:   fmt.Sprintf("unknown check %q (wired checks: doctor, bounded-fixture, install-smoke, reboot-survival, self-update, dogfood)", name),
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

// runRebootSurvivalCheck wires the REAL reboot + liveness probe into the #110
// two-phase state machine. ResumeOrArm dispatches: if a run is armed (persisted
// state present) it resumes (Phase 2 — verify the service came back); otherwise
// it arms (Phase 1 — persist + real reboot). The real reboot only fires under
// --safety disruptive --allow-reboot (enforced by the Runner AND the arm phase);
// the first real-machine exercise is a deferred ready-for-human slice — running
// this on the operator box with the flag really reboots it.
func runRebootSurvivalCheck(ctx context.Context, allowReboot bool) validate.CheckResult {
	statePath, err := validate.DefaultRebootStatePath()
	if err != nil {
		return validate.CheckResult{Name: "reboot-survival", State: "fail", Raw: "resolve reboot state path: " + err.Error()}
	}
	rs := &validate.RebootSurvival{
		StatePath:   statePath,
		Target:      "this-machine",
		AllowReboot: allowReboot,
		EnsureInstalled: func() error {
			// Phase 1 precondition: doctor must not report a hard failure
			// (a missing install can't survive a reboot it never had).
			cfgPath, e := agent.ResolveConfigPath()
			if e != nil {
				return e
			}
			cfg, e := agent.LoadConfig(cfgPath)
			if e != nil {
				return e
			}
			if code := gatekeeper.Doctor(ctx, cfg).ExitCode(); code == 2 {
				return fmt.Errorf("agent not healthy pre-reboot (doctor exit 2); install/repair before arming reboot-survival")
			}
			return nil
		},
		TriggerReboot:     realReboot,
		VerifyResurrected: realServiceLiveness(ctx),
	}
	return rs.ResumeOrArm(newValidateRunID(), "")
}

// realReboot triggers a real OS reboot. Only ever called from the disruptive
// reboot-survival arm phase under --allow-reboot. OS-specific command.
func realReboot() error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("shutdown", "/r", "/t", "5")
	default:
		// -r reboot; sudo is the operator's responsibility (the whole check is
		// privileged/disruptive).
		cmd = exec.Command("shutdown", "-r", "now")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("reboot command failed: %w\n%s", err, out)
	}
	return nil
}

// realServiceLiveness returns a Phase-2 verifier that checks the agent service
// resurrected after the reboot via doctor's service-running check + the loaded
// config. Healthy = doctor reports the service running and no hard failure.
func realServiceLiveness(ctx context.Context) func() (bool, string) {
	return func() (bool, string) {
		cfgPath, err := agent.ResolveConfigPath()
		if err != nil {
			return false, "resolve config: " + err.Error()
		}
		cfg, err := agent.LoadConfig(cfgPath)
		if err != nil {
			return false, "load config: " + err.Error()
		}
		results := gatekeeper.Doctor(ctx, cfg)
		var buf bytes.Buffer
		_ = writeDoctorJSON(&buf, results, results.ExitCode())
		return results.ExitCode() != 2, buf.String()
	}
}

// newValidateRunID makes a run id for the reboot-survival arm phase, matching
// the validate evidence run-id shape.
func newValidateRunID() string {
	return time.Now().UTC().Format("20060102T150405Z")
}

// runSelfUpdateCheck is the production entry for the #111 self-update
// validation. The orchestration (validate.RunSelfUpdateValidation) is fully
// built + unit-tested with faked update artifacts; binding it to the REAL
// download → checksum → atomic-swap → restart against live release artifacts
// (and a cross-restart `--version` probe) is the deferred ready-for-human
// real-machine exercise. Rather than fake a pass, this returns a warn that
// names the deferral, so an operator running it sees an honest "not yet wired
// to real artifacts" signal instead of a false green.
func runSelfUpdateCheck() validate.CheckResult {
	return validate.CheckResult{
		Name:  "self-update",
		State: "warn",
		Raw: "self-update orchestration is built + unit-tested (happy + rollback) with faked artifacts; " +
			"the real download/checksum/atomic-swap against live release artifacts is the deferred " +
			"ready-for-human real-machine exercise (#111). Not run here.",
	}
}

// runDogfoodCheck is the production entry for the #112 dogfood validation. The
// harness + product-vs-transport classifier (validate.RunDogfood /
// ClassifyDogfood) are fully built + unit-tested with fakes for every branch.
// Binding the plain-ssh control + the `uncluster ssh <target> -- hostname` path
// to a LIVE deployment (control plane + ≥2 agents + plain-ssh creds) is the
// deferred ready-for-human exercise. Rather than fake a pass, this reports an
// honest warn (correctly classified indeterminate — no plain-ssh control is
// configured here) so an operator sees the deferral, not a false green.
func runDogfoodCheck(target string) validate.CheckResult {
	if target == "" || target == "this-machine" {
		return validate.CheckResult{
			Name:  "dogfood",
			State: "warn",
			Raw:   "dogfood needs a remote --target <agent-name>; the harness + classifier are built + unit-tested with fakes. Real cross-machine dogfood (live CP + agents + plain-ssh control) is the deferred ready-for-human exercise (#112). Not run here.",
		}
	}
	// No plain-ssh control / live deployment wired in this context → the
	// classifier correctly yields indeterminate (warn), never a false product
	// pass/fail. The real probes are the deferred exercise.
	return validate.RunDogfood(validate.DogfoodOpts{
		Target:            target,
		ControlConfigured: false,
		UnclusterSSH: func() (bool, string) {
			return false, "real `uncluster ssh` dogfood probe is the deferred ready-for-human exercise (#112)"
		},
	}).CheckResult()
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
