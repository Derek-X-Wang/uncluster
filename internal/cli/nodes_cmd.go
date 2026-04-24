package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/api"
)

func newNodesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nodes",
		Short: "Manage registered nodes",
	}
	cmd.AddCommand(newNodesLsCmd())
	cmd.AddCommand(newNodesShowCmd())
	cmd.AddCommand(newNodesRmCmd())
	return cmd
}

func newNodesLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List registered nodes",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")
			}
			client := NewClient(cfg.Server, cfg.Token)

			var nodes []api.NodeSummary
			if err := client.Do(cmd.Context(), "GET", "/v1/nodes", nil, &nodes); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%-18s %-10s %-10s %s\n", "NAME", "STATUS", "SEEN", "OS")
			for _, n := range nodes {
				seen := "never"
				if n.LastSeenAt != nil {
					ago := time.Since(time.Unix(*n.LastSeenAt, 0)).Round(time.Second)
					seen = fmt.Sprintf("%v ago", ago)
				}
				osStr := ""
				if v, ok := n.Metadata["os"]; ok {
					if s, ok := v.(string); ok {
						osStr = s
					}
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-18s %-10s %-10s %s\n",
					n.Name, n.Status, seen, osStr)
			}
			return nil
		},
	}
}

func newNodesShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name|id>",
		Short: "Show details of a node as formatted JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")
			}
			client := NewClient(cfg.Server, cfg.Token)

			var node api.NodeSummary
			if err := client.Do(cmd.Context(), "GET", "/v1/nodes/"+args[0], nil, &node); err != nil {
				return err
			}

			b, err := json.MarshalIndent(node, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(b))
			return nil
		},
	}
}

func newNodesRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <name|id>",
		Short: "Remove a node",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")
			}
			client := NewClient(cfg.Server, cfg.Token)
			return client.Do(cmd.Context(), "DELETE", "/v1/nodes/"+args[0], nil, nil)
		},
	}
}
