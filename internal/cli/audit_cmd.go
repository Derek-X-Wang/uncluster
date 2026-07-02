package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/api"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Query audit logs",
	}
	cmd.AddCommand(newAuditCertsCmd())
	return cmd
}

func newAuditCertsCmd() *cobra.Command {
	var (
		callerFilter  string
		agentFilter   string
		userFilter    string
		outcomeFilter string
		sinceStr      string
		limit         int
		tail          bool
		jsonOut       bool
	)

	cmd := &cobra.Command{
		Use:   "certs",
		Short: "Query cert issuance events",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := newConfiguredControlPlaneClient()
			if err != nil {
				return err
			}
			q := CertAuditQuery{
				Caller:  callerFilter,
				Agent:   agentFilter,
				User:    userFilter,
				Outcome: outcomeFilter,
				Limit:   limit,
			}
			return runAuditCerts(cmd.Context(), client, cmd.OutOrStdout(), q, sinceStr, tail, jsonOut)
		},
	}

	cmd.Flags().StringVar(&callerFilter, "caller", "", "Filter by caller token ID")
	cmd.Flags().StringVar(&agentFilter, "agent", "", "Filter by target agent ID")
	cmd.Flags().StringVar(&userFilter, "user", "", "Filter by SSH username")
	cmd.Flags().StringVar(&outcomeFilter, "outcome", "", "Filter by outcome: signed|denied")
	cmd.Flags().StringVar(&sinceStr, "since", "", "Show events since duration (e.g. 1h, 30m) or unix timestamp")
	cmd.Flags().IntVar(&limit, "limit", 0, "Max rows to return (default 100)")
	cmd.Flags().BoolVar(&tail, "tail", false, "Follow new events (polled every 2s)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "JSON output")
	return cmd
}

// runAuditCerts queries cert issuance Audit events through the typed client and
// renders them. sinceStr is resolved to q.Since (a bad value is silently
// dropped, matching the prior behavior). In tail mode it re-queries every 2s,
// advancing Since past the newest row seen so far.
func runAuditCerts(ctx context.Context, client ControlPlaneClient, out io.Writer,
	q CertAuditQuery, sinceStr string, tail, jsonOut bool) error {
	if sinceStr != "" {
		if ts, err := parseSinceDuration(sinceStr); err == nil {
			q.Since = ts
		}
	}

	printEvents := func(events []api.CertEventSummary) {
		if jsonOut {
			b, _ := json.MarshalIndent(events, "", "  ")
			fmt.Fprintln(out, string(b))
			return
		}
		for _, e := range events {
			ts := time.Unix(e.TS, 0).Format(time.RFC3339)
			outcome := e.Outcome
			detail := ""
			if e.DenialReason != "" {
				detail = " [" + e.DenialReason + "]"
			} else if e.KeyID != "" {
				detail = " key=" + e.KeyID[:min(16, len(e.KeyID))]
			}
			fmt.Fprintf(out, "%s  %-8s  caller=%-20s  agent=%-22s  user=%s%s\n",
				ts, outcome, trunc(e.CallerTokenID, 20), trunc(e.TargetAgentID, 22), e.Username, detail)
		}
	}

	if !tail {
		events, err := client.ListCertEvents(ctx, q)
		if err != nil {
			return err
		}
		printEvents(events)
		return nil
	}

	// Tail mode: poll every 2 seconds for new rows.
	var lastSeen int64
	for {
		events, err := client.ListCertEvents(ctx, q)
		if err != nil {
			return err
		}
		// Results are newest-first; print in reverse for tail mode.
		for i := len(events) - 1; i >= 0; i-- {
			printEvents([]api.CertEventSummary{events[i]})
			if events[i].TS > lastSeen {
				lastSeen = events[i].TS
			}
		}
		if lastSeen > 0 {
			q.Since = lastSeen + 1
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}

// parseSinceDuration parses "1h", "30m", "3600" etc. into a unix timestamp.
func parseSinceDuration(s string) (int64, error) {
	// Try as plain unix timestamp.
	if ts, err := strconv.ParseInt(s, 10, 64); err == nil {
		return ts, nil
	}
	// Try as Go duration; compute since=now-dur.
	secs, err := parseDurationToSeconds(s)
	if err != nil {
		return 0, err
	}
	return time.Now().Unix() - secs, nil
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
