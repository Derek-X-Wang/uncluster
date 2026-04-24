package cli

import (
	"fmt"

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
		Short: "Register this machine as an agent node with an Uncluster server",
		Long: `Register this machine with an Uncluster control plane using a join token.
The join token must be supplied via --token-stdin or the UNCLUSTER_TOKEN env var.
Never pass the token as a command-line argument.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if server == "" {
				return fmt.Errorf("--server is required")
			}
			if name == "" {
				return fmt.Errorf("--name is required")
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

			cfgPath, err := agent.DefaultConfigPath()
			if err != nil {
				return fmt.Errorf("config path: %w", err)
			}
			cfg := agent.Config{
				Server:     server,
				NodeID:     resp.NodeID,
				NodeName:   name,
				AgentToken: resp.AgentToken,
			}
			if err := agent.SaveConfig(cfgPath, cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "registered: node_id=%s  config=%s\n", resp.NodeID, cfgPath)
			return nil
		},
	}

	join.Flags().StringVar(&server, "server", "", "control plane URL, e.g. https://uncluster.example.com (required)")
	join.Flags().StringVar(&name, "name", "", "human-readable name for this agent node (required)")
	join.Flags().BoolVar(&tokenStdin, "token-stdin", false, "read join token from stdin (first line); alternatively set UNCLUSTER_TOKEN")

	return join
}
