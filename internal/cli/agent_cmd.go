package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/agent"
	"github.com/derek-x-wang/uncluster/internal/api"
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
			a := agent.New(cfg, nil)
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

	install := &cobra.Command{
		Use:   "install",
		Short: "Install the agent as a user service (launchd on macOS, systemd user on Linux)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return svcAction("install")
		},
	}
	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall the agent service",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return svcAction("uninstall")
		},
	}
	cmd.AddCommand(install, uninstall)

	return cmd
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

func svcAction(action string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	svcCfg := &service.Config{
		Name:        "com.uncluster.agent",
		DisplayName: "Uncluster Agent",
		Description: "Uncluster node agent",
		Executable:  exe,
		Arguments:   []string{"agent", "run"},
		Option:      map[string]interface{}{"UserService": true},
	}
	prg := &agentService{}
	s, err := service.New(prg, svcCfg)
	if err != nil {
		return err
	}
	return service.Control(s, action)
}

type agentService struct{}

func (a *agentService) Start(service.Service) error { return nil }
func (a *agentService) Stop(service.Service) error  { return nil }
