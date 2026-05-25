package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/api"
)

func newACLCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "acl",
		Short: "Manage SSH access-control grants",
	}
	cmd.AddCommand(newACLGrantCmd())
	cmd.AddCommand(newACLRevokeCmd())
	cmd.AddCommand(newACLLsCmd())
	return cmd
}

// newACLGrantCmd returns `uncluster acl grant <caller> <agent> --as <user>`.
func newACLGrantCmd() *cobra.Command {
	var username string

	cmd := &cobra.Command{
		Use:   "grant <caller-token-id> <agent-id-or-name>",
		Short: "Allow a caller to SSH to an agent as a given username",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if username == "" {
				return fmt.Errorf("--as <username> is required")
			}
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")
			}
			client := NewClient(cfg.Server, cfg.Token)

			var entry api.ACLEntrySummary
			if err := client.Do(cmd.Context(), "POST", "/v1/acl", api.CreateACLRequest{
				Caller:   args[0],
				Agent:    args[1],
				Username: username,
			}, &entry); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "granted: id=%s caller=%s agent=%s username=%s\n",
				entry.ID, entry.CallerTokenID, entry.AgentID, entry.Username)
			return nil
		},
	}
	cmd.Flags().StringVar(&username, "as", "", "SSH username (required)")
	return cmd
}

// newACLRevokeCmd returns `uncluster acl revoke <caller> <agent> --as <user>`.
// It finds the ACL entry by triple and deletes it.
func newACLRevokeCmd() *cobra.Command {
	var username string

	cmd := &cobra.Command{
		Use:   "revoke <caller-token-id> <agent-id-or-name>",
		Short: "Remove a caller's SSH access to an agent",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if username == "" {
				return fmt.Errorf("--as <username> is required")
			}
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")
			}
			client := NewClient(cfg.Server, cfg.Token)

			// List to find matching entry.
			q := url.Values{}
			q.Set("caller", args[0])
			var entries []api.ACLEntrySummary
			if err := client.Do(cmd.Context(), "GET", "/v1/acl?"+q.Encode(), nil, &entries); err != nil {
				return err
			}
			for _, e := range entries {
				if e.Username == username {
					// Agent matching: check by id or name (API returned agent_id).
					// If args[1] looks like an id (ag_ prefix), compare directly.
					// Otherwise the caller supplied a name; we trust the list result.
					if args[1] == e.AgentID || !isAgentID(args[1]) {
						if err := client.Do(cmd.Context(), "DELETE", "/v1/acl/"+e.ID, nil, nil); err != nil {
							return err
						}
						fmt.Fprintf(cmd.OutOrStdout(), "revoked: id=%s\n", e.ID)
						return nil
					}
				}
			}
			return fmt.Errorf("no ACL entry found for caller=%s agent=%s username=%s", args[0], args[1], username)
		},
	}
	cmd.Flags().StringVar(&username, "as", "", "SSH username (required)")
	return cmd
}

// newACLLsCmd returns `uncluster acl ls [--caller=X] [--agent=Y]`.
func newACLLsCmd() *cobra.Command {
	var callerFilter, agentFilter string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List ACL entries",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")
			}
			client := NewClient(cfg.Server, cfg.Token)

			q := url.Values{}
			if callerFilter != "" {
				q.Set("caller", callerFilter)
			}
			if agentFilter != "" {
				q.Set("agent", agentFilter)
			}
			path := "/v1/acl"
			if len(q) > 0 {
				path += "?" + q.Encode()
			}

			var entries []api.ACLEntrySummary
			if err := client.Do(cmd.Context(), "GET", path, nil, &entries); err != nil {
				return err
			}

			if asJSON {
				b, _ := json.MarshalIndent(entries, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return nil
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%-28s %-28s %-20s %-12s %s\n",
				"ID", "CALLER", "AGENT", "USERNAME", "CREATED")
			for _, e := range entries {
				fmt.Fprintf(cmd.OutOrStdout(), "%-28s %-28s %-20s %-12s %s\n",
					e.ID, e.CallerTokenID, e.AgentID, e.Username,
					time.Unix(e.CreatedAt, 0).Format(time.RFC3339))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&callerFilter, "caller", "", "filter by caller token id")
	cmd.Flags().StringVar(&agentFilter, "agent", "", "filter by agent id")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

func isAgentID(s string) bool {
	return len(s) > 3 && s[:3] == "ag_"
}
