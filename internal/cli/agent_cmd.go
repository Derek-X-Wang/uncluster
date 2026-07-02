package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/agent"
	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/gatekeeper"
)

// RunAgent executes one full lifecycle of the agent run loop: loads the
// resolved on-disk config, refuses to start on the .deprovisioned marker,
// and blocks on Agent.Run until ctx is cancelled or the agent exits.
//
// This function is the single source of truth for the agent's foreground
// run behaviour. It is called from:
//   - the `uncluster agent run` cobra command (terminal / systemd / launchd
//     foreground execution)
//   - the Windows SCM handler (`cmd/uncluster/agent_run_windows.go`),
//     which wraps it under svc.Run so the binary completes the SCM
//     control-handler handshake (see #88)
//
// Diagnostic output is written to stderrW (the supervisor's stderr stream
// or a redirect for the SCM handler). The function returns nil for the
// graceful termination paths (deprovisioned, unauthorized, marker present)
// so the supervisor does not interpret them as crashes and restart against
// a revoked token.
func RunAgent(ctx context.Context, stderrW io.Writer) error {
	if stderrW == nil {
		stderrW = os.Stderr
	}
	// Prefer the system-wide path so the service account (which has
	// a different HOME than the operator who ran `agent join`) can
	// read it. Falls back to per-user for ad-hoc / pre-install runs.
	// See #77 for the original bug.
	p, err := agent.ResolveConfigPath()
	if err != nil {
		return err
	}
	cfg, err := agent.LoadConfig(p)
	if err != nil {
		return fmt.Errorf("load agent config: %w", err)
	}
	if cfg.Server == "" || cfg.AgentToken == "" {
		return fmt.Errorf("agent not joined; run `uncluster agent join` first")
	}
	// Log the resolved path at startup so the operator can grep
	// journalctl/Event Viewer to confirm which file the service
	// actually loaded (#77 acceptance).
	slog.Info("agent: loaded config", "path", p)
	a := agent.New(cfg, nil).
		WithConfigPath(p).
		WithDeprovisionCleanup(deprovisionCleanupHook()).
		WithHealthProvider(
			func(ctx context.Context) ([]api.AgentHealthCheck, error) {
				// Surface the loaded config path first so the
				// operator can confirm via the agent's heartbeat
				// that the service is reading the system path,
				// not silently falling back to a stale per-user
				// copy. DoctorResults.HealthChecks is the SINGLE
				// doctor → wire-shape mapping (#104) — the same one
				// `agent doctor --json` uses — so the heartbeat and
				// doctor never drift. FullDoctor is the single check
				// composition shared by every call site (#143).
				//
				// FullDoctor does not return an error today (it maps
				// every probe to a check with its own state), so this
				// returns nil; the (checks, error) contract exists so
				// a future erroring source — or a panic, which the
				// agent recovers — surfaces as a synthetic failed
				// check rather than an empty health slice (#150).
				results := gatekeeper.FullDoctor(ctx, cfg, p)
				return results.HealthChecks(), nil
			},
		)
	// Refuse to start if a .deprovisioned marker exists next to
	// agent.toml. The supervisor would otherwise flap-restart us
	// against a revoked token, which the operator has to manually
	// untangle (#46).
	if _, err := os.Stat(a.DeprovisionedMarkerPath()); err == nil {
		fmt.Fprintln(stderrW,
			"agent: previously deprovisioned by control plane; uninstall the service unit manually (see `uncluster agent install --help`).")
		return nil
	}
	if err := a.Run(ctx); err != nil {
		switch {
		case errors.Is(err, agent.ErrDeprovisioned):
			// 410-Gone path: onRevoked wiped principals and wrote
			// the marker. Exit 0 so the service supervisor does NOT
			// restart us (per ACCEPTANCE.md §44).
			fmt.Fprintln(stderrW,
				"agent: deprovisioned by control plane; principals wiped, supervisor should not restart")
			return nil
		case errors.Is(err, agent.ErrUnauthorized):
			// 401 path: token revoked at the token layer but agent
			// record is still enrolled. Principals preserved; operator
			// must intervene (re-issue agent token or remove agent).
			fmt.Fprintln(stderrW,
				"agent: unauthorized; agent token revoked or rotated; operator intervention required")
			return nil
		}
		return err
	}
	return nil
}

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Manage the Uncluster agent on this machine",
	}
	cmd.AddCommand(newAgentJoinCmd())

	run := &cobra.Command{
		Use:   "run",
		Short: "Run the agent in the foreground (used by service units)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The actual run logic is in RunAgent so the Windows SCM
			// handler (cmd/uncluster/agent_run_windows.go) can share
			// the same entry point. See #88.
			return RunAgent(cmd.Context(), cmd.ErrOrStderr())
		},
	}
	cmd.AddCommand(run)

	install := newAgentInstallCmd()
	cmd.AddCommand(install)

	doctor := newAgentDoctorCmd()
	cmd.AddCommand(doctor)

	cmd.AddCommand(newAgentUpdateCmd())
	cmd.AddCommand(newAgentRollbackCmd())

	return cmd
}

func newAgentInstallCmd() *cobra.Command {
	// Future flag: --update-host=<host> (repeatable) to set
	// Config.UpdateHostAllowlist at install time. Not wired in this slice
	// per #39 brief ("reserve the name and document it as planned").
	// When implemented, the flag values overwrite
	// agent.toml's update_host_allowlist BEFORE the file is copied to the
	// system path. Operators who want to disable updates pass --update-host=
	// once with an empty value (translates to []string{}); operators who
	// want the default pass no flag (leaves the field unset; loader uses
	// DefaultUpdateHostAllowlist).
	return &cobra.Command{
		Use:   "install",
		Short: "Privileged install: configure sshd, create service account, and start system service (requires root)",
		Long: `Writes CA pubkey and sshd drop-in config, creates the low-priv service account,
installs the agent as a system service (launchd on macOS, systemd on Linux),
and reloads sshd. Must run as root (sudo).

Re-running is safe — install is idempotent and self-heals drift.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Source of truth for install is the per-user path (where
			// `agent join` wrote it). After install we copy it to the
			// system path so the service can read it (#77).
			cfgPath, err := agent.DefaultConfigPath()
			if err != nil {
				return err
			}
			cfg, err := agent.LoadConfig(cfgPath)
			if err != nil {
				return fmt.Errorf("load agent config: %w (run `uncluster agent join` first)", err)
			}
			if cfg.AgentToken == "" {
				return fmt.Errorf("agent not enrolled; run `uncluster agent join` first")
			}
			if cfg.CAPubkey == "" {
				return fmt.Errorf("CA pubkey missing from agent config; re-enroll")
			}

			exe, err := os.Executable()
			if err != nil {
				return fmt.Errorf("resolve executable: %w", err)
			}

			// gatekeeper.Install handles copying agent.toml to the
			// system-wide path at the right sequenced step (after the
			// service account/SID exists, before the service starts).
			// Previous design did this from the CLI layer in two passes
			// flanking Install — but Install's `startService` ran
			// between the two passes, so the service tried to start
			// with the wrong-ownership file and entered systemd's
			// restart backoff before the second pass could fix it. See
			// the hotfix on #77 for the bug rationale.
			if err := gatekeeper.Install(cmd.Context(), cfg, exe); err != nil {
				return fmt.Errorf("install: %w", err)
			}

			fmt.Fprintln(cmd.OutOrStdout(), "install complete — run `uncluster agent doctor` to verify")
			return nil
		},
	}
}

func newAgentDoctorCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check gatekeeper configuration state (no mutations). Exit 0=ok, 1=warn, 2=fail.",
		Long: `Runs the gatekeeper health checks and reports each one. Performs ZERO
filesystem mutations on every platform — it only reads (stat, file reads,
read-only service queries), so it is safe to invoke automatically (the
ADR-0009 inspect contract).

With --json, emits the structured check set (the same api.AgentHealthCheck
shape the agent reports on its heartbeat) so CI, the validate skill, and
dogfood all parse ONE definition of "healthy". Exit code is still 0=ok,
1=warn, 2=fail in both modes.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Doctor reads — prefer the system path so a post-install run
			// reflects what the service sees.
			cfgPath, err := agent.ResolveConfigPath()
			if err != nil {
				return err
			}
			cfg, err := agent.LoadConfig(cfgPath)
			if err != nil {
				return fmt.Errorf("load agent config: %w", err)
			}

			// Prepend the loaded-path check so the operator sees up-front
			// which file doctor is reasoning about. Especially useful
			// post-install to confirm the system path was populated (#77).
			results := gatekeeper.FullDoctor(cmd.Context(), cfg, cfgPath)

			code := results.ExitCode()

			if jsonOut {
				if err := writeDoctorJSON(cmd.OutOrStdout(), results, code); err != nil {
					return err
				}
			} else {
				statusLabel := map[gatekeeper.CheckStatus]string{
					gatekeeper.CheckOK:   "ok  ",
					gatekeeper.CheckWarn: "warn",
					gatekeeper.CheckFail: "FAIL",
				}
				for _, r := range results {
					fmt.Fprintf(cmd.OutOrStdout(), "[%s] %-30s %s\n", statusLabel[r.Status], r.Name, r.Message)
				}
			}

			if code != 0 {
				// Return a typed error so cobra prints nothing extra but os.Exit
				// still gets the right code via the root command's exit handler.
				// In --json mode the JSON has already been written to stdout, so
				// the structured output AND the exit code both reach the caller.
				return &exitCodeError{code: code}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit structured health checks as JSON (single source of truth shape)")
	return cmd
}

// doctorJSON is the documented schema for `uncluster agent doctor --json`.
// The future validate skill and CI parse this exact shape. `checks` is the
// wire-identical api.AgentHealthCheck slice the agent reports on its heartbeat;
// `exit_code` mirrors the process exit (0=ok, 1=warn, 2=fail) so a JSON
// consumer need not re-derive the rollup; `summary` gives per-state counts for
// terse assertions.
type doctorJSON struct {
	Checks   []api.AgentHealthCheck `json:"checks"`
	ExitCode int                    `json:"exit_code"`
	Summary  doctorSummary          `json:"summary"`
}

type doctorSummary struct {
	OK   int `json:"ok"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

// writeDoctorJSON renders the doctor results as the documented doctorJSON
// schema. Extracted so it is unit-testable without a live config/sshd host.
func writeDoctorJSON(w io.Writer, results gatekeeper.DoctorResults, exitCode int) error {
	out := doctorJSON{
		Checks:   results.HealthChecks(),
		ExitCode: exitCode,
	}
	for _, r := range results {
		switch r.Status {
		case gatekeeper.CheckOK:
			out.Summary.OK++
		case gatekeeper.CheckWarn:
			out.Summary.Warn++
		case gatekeeper.CheckFail:
			out.Summary.Fail++
		}
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal doctor json: %w", err)
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}

func newAgentJoinCmd() *cobra.Command {
	var (
		server     string
		name       string
		tokenStdin bool
	)

	join := &cobra.Command{
		Use:   "join",
		Short: "Register this machine as an Agent with an Uncluster Control plane",
		Long: `Register this machine with an Uncluster control plane using a join token.
The join token must be supplied via --token-stdin or the UNCLUSTER_TOKEN env var.
Never pass the token as a command-line argument.

If this machine is already enrolled (agent.toml already exists with a token),
this command returns an error. Run ` + "`uncluster agent install`" + ` instead, which
is self-healing.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if server == "" {
				return fmt.Errorf("--server is required")
			}
			if name == "" {
				return fmt.Errorf("--name is required")
			}

			cfgPath, err := agent.DefaultConfigPath()
			if err != nil {
				return fmt.Errorf("config path: %w", err)
			}

			// Idempotency-by-rejection: if already enrolled, refuse.
			if existing, err := agent.LoadConfig(cfgPath); err == nil && existing.AgentToken != "" {
				return fmt.Errorf("already enrolled (agent_id=%s); remove %s to re-enroll", existing.AgentID, cfgPath)
			}

			tok, err := ReadSecretToken(tokenStdin)
			if err != nil {
				return err
			}

			client := agent.NewServerClient(server, "")
			resp, err := client.Register(cmd.Context(), api.AgentRegisterRequest{
				JoinToken: tok,
				Name:      name,
				Metadata:  agent.CollectMetrics(),
			})
			if err != nil {
				return fmt.Errorf("register: %w", err)
			}

			cfg := agent.Config{
				Server:         server,
				AgentID:        resp.AgentID,
				AgentName:      name,
				AgentToken:     resp.AgentToken,
				CAPubkey:       resp.CAPubkey,
				ServerHTTPSPin: resp.ServerHTTPSPin,
				ExpectedPaths: agent.ExpectedPaths{
					CAPubkey:      resp.ExpectedPaths.CAPubkey,
					SSHDropIn:     resp.ExpectedPaths.SSHDropIn,
					PrincipalsDir: resp.ExpectedPaths.PrincipalsDir,
				},
			}
			if err := agent.SaveConfig(cfgPath, cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "registered: agent_id=%s  config=%s\n", resp.AgentID, cfgPath)
			return nil
		},
	}

	join.Flags().StringVar(&server, "server", "", "control plane URL, e.g. https://uncluster.example.com (required)")
	join.Flags().StringVar(&name, "name", "", "human-readable name for this Agent (required)")
	join.Flags().BoolVar(&tokenStdin, "token-stdin", false, "read join token from stdin (first line); alternatively set UNCLUSTER_TOKEN")

	return join
}

// exitCodeError is a sentinel that carries a non-zero exit code without
// printing an error message (cobra prints the message from error.Error()).
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return "" }
func (e *exitCodeError) ExitCode() int { return e.code }
