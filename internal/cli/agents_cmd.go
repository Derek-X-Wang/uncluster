package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/api"
)

func newAgentsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agents",
		Short: "Manage V2 agents",
	}
	cmd.AddCommand(newAgentsLsCmd())
	cmd.AddCommand(newAgentsRmCmd())
	cmd.AddCommand(newAgentsSetCmd())
	return cmd
}

func newAgentsLsCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List registered agents",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")
			}
			client := NewClient(cfg.Server, cfg.Token)

			var agents []api.AgentDetail
			if err := client.Do(cmd.Context(), "GET", "/v1/agents", nil, &agents); err != nil {
				return err
			}

			if jsonOut {
				b, _ := json.MarshalIndent(agents, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return nil
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%-22s %-20s %-10s %-10s %s\n",
				"ID", "NAME", "STATUS", "SEEN", "VERSION")
			for _, ag := range agents {
				seen := "never"
				if ag.LastSeenAt != nil {
					ago := time.Since(time.Unix(*ag.LastSeenAt, 0)).Round(time.Second)
					seen = relTime(ago)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-22s %-20s %-10s %-10s %s\n",
					ag.ID, ag.Name, ag.Status, seen, ag.AgentVersion)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "JSON output")
	return cmd
}

func newAgentsRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <name|id>",
		Short: "Revoke and remove an agent",
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
			if err := client.Do(cmd.Context(), "DELETE", "/v1/agents/"+args[0], nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "agent %s revoked\n", args[0])
			return nil
		},
	}
}

func newAgentsSetCmd() *cobra.Command {
	var failClosedAfter string
	cmd := &cobra.Command{
		Use:   "set <name|id>",
		Short: "Update agent settings",
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

			body := map[string]any{}
			if cmd.Flags().Changed("fail-closed-after") {
				if failClosedAfter == "" || failClosedAfter == "0" {
					body["fail_closed_after"] = nil
				} else {
					secs, err := parseDurationToSeconds(failClosedAfter)
					if err != nil {
						return fmt.Errorf("invalid --fail-closed-after: %w", err)
					}
					body["fail_closed_after"] = secs
				}
			}
			if len(body) == 0 {
				return fmt.Errorf("no fields to update; use --fail-closed-after=<duration>")
			}
			return client.Do(cmd.Context(), "PATCH", "/v1/agents/"+args[0], body, nil)
		},
	}
	cmd.Flags().StringVar(&failClosedAfter, "fail-closed-after", "", "Duration after which principals are wiped on disconnect (e.g. 1h, 30m, 3600s, or 0 to clear)")
	return cmd
}

// parseDurationToSeconds parses a Go duration string or plain seconds integer
// into an int64 of seconds. Accepts: "3600", "3600s", "1h", "30m", "1h30m".
func parseDurationToSeconds(s string) (int64, error) {
	// Plain integer = seconds.
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	// "<N>s" — plain seconds with suffix.
	if strings.HasSuffix(s, "s") {
		if n, err := strconv.ParseInt(strings.TrimSuffix(s, "s"), 10, 64); err == nil {
			return n, nil
		}
	}
	// Go duration string (1h, 30m, 1h30m, etc.)
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	return int64(d.Seconds()), nil
}

func relTime(ago time.Duration) string {
	switch {
	case ago < 30*time.Second:
		return "just now"
	case ago < time.Minute:
		return fmt.Sprintf("%ds ago", int(ago.Seconds()))
	case ago < time.Hour:
		return fmt.Sprintf("%dm ago", int(ago.Minutes()))
	default:
		return fmt.Sprintf("%dh ago", int(ago.Hours()))
	}
}
