package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
			cfg, client, err := loadConfiguredCLI()
			if err != nil {
				return err
			}
			return runAgentsList(cmd.Context(), client, cmd.OutOrStdout(),
				cfg.Subnets, time.Now(), jsonOut, subnetFilter, statusFilter)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "JSON output")
	cmd.Flags().StringVar(&subnetFilter, "subnet", "", "Filter to agents on subnet X")
	cmd.Flags().StringVar(&statusFilter, "status", "", "Filter by computed status: online|stale|offline")
	return cmd
}

// runAgentsList lists agents through the typed client, computing status/best
// endpoint relative to now (injected for deterministic tests) and honoring the
// subnet/status filters. callerSubnets biases best-endpoint selection.
func runAgentsList(ctx context.Context, client ControlPlaneClient, out io.Writer,
	callerSubnets []string, now time.Time, jsonOut bool, subnetFilter, statusFilter string) error {
	agents, err := client.ListAgents(ctx)
	if err != nil {
		return err
	}

	type row struct {
		ag     api.AgentDetail
		seen   time.Duration // negative means never
		status string        // computed: online|stale|offline
		bestEP string        // best endpoint address for caller's subnets
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

		// Build subnet list for the subnet filter.
		var subnetNames []string
		for _, ep := range ag.Endpoints {
			subnetNames = append(subnetNames, ep.Subnet)
		}
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
			if len(callerSubnets) > 0 {
				callerSet := map[string]bool{}
				for _, s := range callerSubnets {
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

		rows = append(rows, row{ag: ag, seen: seen, status: computedStatus, bestEP: bestEP})
	}

	if jsonOut {
		b, _ := json.MarshalIndent(agents, "", "  ")
		fmt.Fprintln(out, string(b))
		return nil
	}

	fmt.Fprintf(out, "%-20s %-20s %-8s %-20s %-12s %s\n",
		"NAME", "ID", "STATUS", "ENDPOINT", "SEEN", "VERSION")
	for _, r := range rows {
		seenStr := "never"
		if r.ag.LastSeenAt != nil {
			seenStr = relTime(r.seen)
		}
		fmt.Fprintf(out, "%-20s %-20s %-8s %-20s %-12s %s\n",
			r.ag.Name, r.ag.ID, r.status, r.bestEP, seenStr, r.ag.AgentVersion)
	}
	return nil
}

func newAgentsRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <name|id>",
		Short: "Revoke and remove an agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newConfiguredControlPlaneClient()
			if err != nil {
				return err
			}
			return runAgentsRemove(cmd.Context(), client, cmd.OutOrStdout(), args[0])
		},
	}
}

// runAgentsRemove revokes and removes an agent through the typed client.
func runAgentsRemove(ctx context.Context, client ControlPlaneClient, out io.Writer, idOrName string) error {
	if err := client.RemoveAgent(ctx, idOrName); err != nil {
		return err
	}
	fmt.Fprintf(out, "agent %s revoked\n", idOrName)
	return nil
}

func newAgentsSetCmd() *cobra.Command {
	var failClosedAfter string
	cmd := &cobra.Command{
		Use:   "set <name|id>",
		Short: "Update agent settings",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newConfiguredControlPlaneClient()
			if err != nil {
				return err
			}
			return runAgentsSet(cmd.Context(), client, args[0],
				cmd.Flags().Changed("fail-closed-after"), failClosedAfter)
		},
	}
	cmd.Flags().StringVar(&failClosedAfter, "fail-closed-after", "", "Duration after which principals are wiped on disconnect (e.g. 1h, 30m, 3600s, or 0 to clear)")
	return cmd
}

// runAgentsSet updates agent settings through the typed client. failClosedChanged
// reports whether the --fail-closed-after flag was set; an empty or "0" value
// clears the window (nil seconds), any other value parses to seconds.
func runAgentsSet(ctx context.Context, client ControlPlaneClient, idOrName string, failClosedChanged bool, failClosedAfter string) error {
	if !failClosedChanged {
		return fmt.Errorf("no fields to update; use --fail-closed-after=<duration>")
	}
	var seconds *int64
	if failClosedAfter != "" && failClosedAfter != "0" {
		secs, err := parseDurationToSeconds(failClosedAfter)
		if err != nil {
			return fmt.Errorf("invalid --fail-closed-after: %w", err)
		}
		seconds = &secs
	}
	return client.SetAgentFailClosedAfter(ctx, idOrName, seconds)
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
