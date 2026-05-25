package cli

import (
	"encoding/json"
	"fmt"
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
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")
			}
			client := NewClient(cfg.Server, cfg.Token)

			buildQuery := func(lastSeen int64) string {
				q := "/v1/audit/certs?"
				if callerFilter != "" {
					q += "caller=" + callerFilter + "&"
				}
				if agentFilter != "" {
					q += "agent=" + agentFilter + "&"
				}
				if userFilter != "" {
					q += "user=" + userFilter + "&"
				}
				if outcomeFilter != "" {
					q += "outcome=" + outcomeFilter + "&"
				}
				if sinceStr != "" && lastSeen == 0 {
					ts, err := parseSinceDuration(sinceStr)
					if err == nil {
						q += "since=" + strconv.FormatInt(ts, 10) + "&"
					}
				} else if lastSeen > 0 {
					q += "since=" + strconv.FormatInt(lastSeen+1, 10) + "&"
				}
				if limit > 0 {
					q += "limit=" + strconv.Itoa(limit) + "&"
				}
				return q
			}

			fetch := func(lastSeen int64) ([]api.CertEventSummary, error) {
				var events []api.CertEventSummary
				if err := client.Do(cmd.Context(), "GET", buildQuery(lastSeen), nil, &events); err != nil {
					return nil, err
				}
				return events, nil
			}

			printEvents := func(events []api.CertEventSummary) {
				if jsonOut {
					b, _ := json.MarshalIndent(events, "", "  ")
					fmt.Fprintln(cmd.OutOrStdout(), string(b))
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
					fmt.Fprintf(cmd.OutOrStdout(), "%s  %-8s  caller=%-20s  agent=%-22s  user=%s%s\n",
						ts, outcome, trunc(e.CallerTokenID, 20), trunc(e.TargetAgentID, 22), e.Username, detail)
				}
			}

			if !tail {
				events, err := fetch(0)
				if err != nil {
					return err
				}
				printEvents(events)
				return nil
			}

			// Tail mode: poll every 2 seconds for new rows.
			var lastSeen int64
			for {
				events, err := fetch(lastSeen)
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
				select {
				case <-cmd.Context().Done():
					return nil
				case <-time.After(2 * time.Second):
				}
			}
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
