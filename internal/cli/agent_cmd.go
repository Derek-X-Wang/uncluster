package cli

import (
	"context"
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
		WithHealthProvider(
			func(ctx context.Context) []api.AgentHealthCheck {
				// Surface the loaded config path first so the
				// operator can confirm via the agent's heartbeat
				// that the service is reading the system path,
				// not silently falling back to a stale per-user
				// copy.
				results := append(
					gatekeeper.DoctorResults{
						gatekeeper.CheckConfigLoadedPath(p),
						gatekeeper.CheckUpdateHostAllowlist(cfg.AllowedUpdateHosts()),
					},
					gatekeeper.Doctor(ctx, cfg)...,
				)
				checks := make([]api.AgentHealthCheck, 0, len(results))
				for _, r := range results {
					hc := api.AgentHealthCheck{
						Component: gatekeeperComponent(r.Name),
						Check:     gatekeeperCheck(r.Name),
						State:     gatekeeperState(r.Status),
					}
					// Always include the message for informational
					// checks (config-loaded-path, update-host-allowlist)
					// because the message IS the payload — the OK
					// status alone tells the operator nothing useful.
					if r.Message != "" && (r.Informational || r.Status != gatekeeper.CheckOK) {
						msg := r.Message
						hc.Message = &msg
					}
					checks = append(checks, hc)
				}
				return checks
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
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check gatekeeper configuration state (no mutations). Exit 0=ok, 1=warn, 2=fail.",
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
			results := append(
				gatekeeper.DoctorResults{
					gatekeeper.CheckConfigLoadedPath(cfgPath),
					gatekeeper.CheckUpdateHostAllowlist(cfg.AllowedUpdateHosts()),
				},
				gatekeeper.Doctor(cmd.Context(), cfg)...,
			)

			statusLabel := map[gatekeeper.CheckStatus]string{
				gatekeeper.CheckOK:   "ok  ",
				gatekeeper.CheckWarn: "warn",
				gatekeeper.CheckFail: "FAIL",
			}
			for _, r := range results {
				fmt.Fprintf(cmd.OutOrStdout(), "[%s] %-30s %s\n", statusLabel[r.Status], r.Name, r.Message)
			}

			code := results.ExitCode()
			if code != 0 {
				// Return a typed error so cobra prints nothing extra but os.Exit
				// still gets the right code via the root command's exit handler.
				return &exitCodeError{code: code}
			}
			return nil
		},
	}
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
				Server:     server,
				AgentID:    resp.AgentID,
				AgentName:  name,
				AgentToken: resp.AgentToken,
				CAPubkey:   resp.CAPubkey,
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

// gatekeeperComponent maps a doctor check name to the component field for
// the V2 heartbeat health shape.
func gatekeeperComponent(name string) string {
	switch name {
	case "sshd-binary", "sshd-running", "sshd-drop-in", "sshd-effective-config", "macos-include":
		return "sshd"
	case "ca-pubkey":
		return "ca_pubkey"
	case "principals-dir":
		return "principals"
	case "service-account":
		return "service_account"
	case "service-running":
		return "service"
	case "config-loaded-path":
		return "config"
	case "update-host-allowlist":
		return "selfupdate"
	default:
		return name
	}
}

// gatekeeperCheck maps a doctor check name to the check field.
func gatekeeperCheck(name string) string {
	switch name {
	case "sshd-binary":
		return "installed"
	case "sshd-running", "service-running":
		return "running"
	case "sshd-drop-in":
		return "config_drop_in"
	case "sshd-effective-config":
		return "effective_config"
	case "ca-pubkey":
		return "present"
	case "principals-dir":
		return "dir_writable"
	case "service-account":
		return "exists"
	case "macos-include":
		return "include_directive"
	case "config-loaded-path":
		return "loaded_path"
	case "update-host-allowlist":
		return "host_allowlist"
	default:
		return name
	}
}

// gatekeeperState maps a doctor CheckStatus to the state string.
func gatekeeperState(s gatekeeper.CheckStatus) string {
	switch s {
	case gatekeeper.CheckOK:
		return "ok"
	case gatekeeper.CheckWarn:
		return "warn"
	case gatekeeper.CheckFail:
		return "fail"
	default:
		return "unknown"
	}
}

// exitCodeError is a sentinel that carries a non-zero exit code without
// printing an error message (cobra prints the message from error.Error()).
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return "" }
func (e *exitCodeError) ExitCode() int { return e.code }
