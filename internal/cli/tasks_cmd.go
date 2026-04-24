package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/api"
)

func newTasksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tasks",
		Short: "Inspect and stream task output",
	}
	cmd.AddCommand(newTasksTailCmd())
	cmd.AddCommand(newTasksShowCmd())
	cmd.AddCommand(newTasksLsCmd())
	return cmd
}

func newTasksTailCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tail <id>",
		Short: "Stream live output for a task (connects to SSE stream)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			taskID := args[0]
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")
			}
			client := NewClient(cfg.Server, cfg.Token)
			return tailTask(cmd.Context(), client, taskID)
		},
	}
}

func newTasksShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <id>",
		Short: "Show details of a task as formatted JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			taskID := args[0]
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")
			}
			client := NewClient(cfg.Server, cfg.Token)

			var detail api.TaskDetail
			if err := client.Do(cmd.Context(), "GET", "/v1/tasks/"+taskID, nil, &detail); err != nil {
				return err
			}

			b, err := json.MarshalIndent(detail, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(b))
			return nil
		},
	}
}

func newTasksLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List recent tasks",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")
			}
			client := NewClient(cfg.Server, cfg.Token)

			var tasks []api.TaskDetail
			if err := client.Do(cmd.Context(), "GET", "/v1/tasks", nil, &tasks); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%-26s %-12s %-10s %s\n", "ID", "STATUS", "NODE", "COMMAND")
			for _, t := range tasks {
				fmt.Fprintf(cmd.OutOrStdout(), "%-26s %-12s %-10s %s\n",
					t.ID, t.Status, t.NodeID, t.Command)
			}
			return nil
		},
	}
}
