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
	var (
		jsonOut      bool
		subnetFilter string
		statusFilter string
	)
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List registered agents",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; run `uncluster config init`")
			}
			client := NewClient(cfg.Server, cfg.Token)

			var agents []api.AgentDetail
			if err := client.Do(cmd.Context(), "GET", "/v1/agents", nil, &agents); err != nil {
				return err
			}

			// Compute staleness and filter.
			now := time.Now()
			type row struct {
				ag      api.AgentDetail
				seen    time.Duration // negative means never
				status  string        // computed: online|stale|offline
				bestEP  string        // best endpoint address for caller's subnets
				subnets string        // comma-sep subnet names
			}
			var rows []row
			for _, ag := range agents {
				var seen time.Duration
				var computedStatus string
				if ag.LastSeenAt == nil {
					computedStatus = "offline"
				} else {
					seen = now.Sub(time.Unix(*ag.LastSeenAt, 0))
					switch {
					case seen < 30*time.Second:
						computedStatus = "online"
					case seen < time.Hour:
						computedStatus = "stale"
					default:
						computedStatus = "offline"
					}
				}

				// Filter by status.
				if statusFilter != "" && computedStatus != statusFilter {
					continue
				}

				// Build subnet list and best endpoint.
				var subnetNames []string
				for _, ep := range ag.Endpoints {
					subnetNames = append(subnetNames, ep.Subnet)
				}

				// Filter by subnet.
				if subnetFilter != "" {
					found := false
					for _, sn := range subnetNames {
						if sn == subnetFilter {
							found = true
							break
						}
					}
					if !found {
						continue
					}
				}

				// Pick best endpoint: first overlap with caller's subnets, then first.
				bestEP := ""
				if len(ag.Endpoints) > 0 {
					bestEP = ag.Endpoints[0].Address
					if len(cfg.Subnets) > 0 {
						callerSet := map[string]bool{}
						for _, s := range cfg.Subnets {
							callerSet[s] = true
						}
						for _, ep := range ag.Endpoints {
							if callerSet[ep.Subnet] {
								bestEP = ep.Address
								break
							}
						}
					}
				}

				rows = append(rows, row{
					ag:      ag,
					seen:    seen,
					status:  computedStatus,
					bestEP:  bestEP,
					subnets: strings.Join(subnetNames, ","),
				})
			}

			if jsonOut {
				b, _ := json.MarshalIndent(agents, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return nil
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%-20s %-20s %-8s %-20s %-12s %s\n",
				"NAME", "ID", "STATUS", "ENDPOINT", "SEEN", "VERSION")
			for _, r := range rows {
				seenStr := "never"
				if r.ag.LastSeenAt != nil {
					seenStr = relTime(r.seen)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-20s %-20s %-8s %-20s %-12s %s\n",
					r.ag.Name, r.ag.ID, r.status, r.bestEP, seenStr, r.ag.AgentVersion)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "JSON output")
	cmd.Flags().StringVar(&subnetFilter, "subnet", "", "Filter to agents on subnet X")
	cmd.Flags().StringVar(&statusFilter, "status", "", "Filter by computed status: online|stale|offline")
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
		// ISO timestamp for >1h — caller can reconstruct exact time.
		return time.Now().Add(-ago).Format(time.RFC3339)
	}
}
