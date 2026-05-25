package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/agent"
	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/gatekeeper"
)

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
			p, err := agent.DefaultConfigPath()
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
			a := agent.New(cfg, nil).WithHealthProvider(
				func(ctx context.Context) []api.AgentHealthCheck {
					results := gatekeeper.Doctor(ctx, cfg)
					checks := make([]api.AgentHealthCheck, 0, len(results))
					for _, r := range results {
						hc := api.AgentHealthCheck{
							Component: gatekeeperComponent(r.Name),
							Check:     gatekeeperCheck(r.Name),
							State:     gatekeeperState(r.Status),
						}
						if r.Message != "" && r.Status != gatekeeper.CheckOK {
							msg := r.Message
							hc.Message = &msg
						}
						checks = append(checks, hc)
					}
					return checks
				},
			)
			if err := a.Run(cmd.Context()); err != nil {
				if errors.Is(err, agent.ErrUnauthorized) {
					fmt.Fprintln(cmd.ErrOrStderr(), "agent: revoked by server; exiting")
					return nil
				}
				return err
			}
			return nil
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
	return &cobra.Command{
		Use:   "install",
		Short: "Privileged install: configure sshd, create service account, and start system service (requires root)",
		Long: `Writes CA pubkey and sshd drop-in config, creates the low-priv service account,
installs the agent as a system service (launchd on macOS, systemd on Linux),
and reloads sshd. Must run as root (sudo).

Re-running is safe — install is idempotent and self-heals drift.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
			cfgPath, err := agent.DefaultConfigPath()
			if err != nil {
				return err
			}
			cfg, err := agent.LoadConfig(cfgPath)
			if err != nil {
				return fmt.Errorf("load agent config: %w", err)
			}

			results := gatekeeper.Doctor(cmd.Context(), cfg)

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
