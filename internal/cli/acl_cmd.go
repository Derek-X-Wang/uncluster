package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
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
			client, err := newConfiguredControlPlaneClient()
			if err != nil {
				return err
			}
			return runACLGrant(cmd.Context(), client, cmd.OutOrStdout(), args[0], args[1], username)
		},
	}
	cmd.Flags().StringVar(&username, "as", "", "SSH username (required)")
	return cmd
}

// runACLGrant grants an ACL through the typed client and prints the result.
func runACLGrant(ctx context.Context, client ControlPlaneClient, out io.Writer, caller, agent, username string) error {
	entry, err := client.GrantACL(ctx, caller, agent, username)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "granted: id=%s caller=%s agent=%s username=%s\n",
		entry.ID, entry.CallerTokenID, entry.AgentID, entry.Username)
	return nil
}

// newACLRevokeCmd returns `uncluster acl revoke <caller> <agent> --as <user>`.
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
			client, err := newConfiguredControlPlaneClient()
			if err != nil {
				return err
			}
			return runACLRevoke(cmd.Context(), client, cmd.OutOrStdout(), args[0], args[1], username)
		},
	}
	cmd.Flags().StringVar(&username, "as", "", "SSH username (required)")
	return cmd
}

// runACLRevoke revokes an ACL through the typed client and prints the result.
func runACLRevoke(ctx context.Context, client ControlPlaneClient, out io.Writer, caller, agent, username string) error {
	entry, err := client.RevokeACL(ctx, caller, agent, username)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "revoked: id=%s\n", entry.ID)
	return nil
}

// newACLLsCmd returns `uncluster acl ls [--caller=X] [--agent=Y]`.
func newACLLsCmd() *cobra.Command {
	var callerFilter, agentFilter string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List ACL entries",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := newConfiguredControlPlaneClient()
			if err != nil {
				return err
			}
			return runACLList(cmd.Context(), client, cmd.OutOrStdout(), callerFilter, agentFilter, asJSON)
		},
	}
	cmd.Flags().StringVar(&callerFilter, "caller", "", "filter by caller token id")
	cmd.Flags().StringVar(&agentFilter, "agent", "", "filter by agent id")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

// runACLList lists ACL entries through the typed client and renders them.
func runACLList(ctx context.Context, client ControlPlaneClient, out io.Writer, callerFilter, agentFilter string, asJSON bool) error {
	entries, err := client.ListACL(ctx, callerFilter, agentFilter)
	if err != nil {
		return err
	}

	if asJSON {
		b, _ := json.MarshalIndent(entries, "", "  ")
		fmt.Fprintln(out, string(b))
		return nil
	}

	fmt.Fprintf(out, "%-28s %-28s %-20s %-12s %s\n",
		"ID", "CALLER", "AGENT", "USERNAME", "CREATED")
	for _, e := range entries {
		fmt.Fprintf(out, "%-28s %-28s %-20s %-12s %s\n",
			e.ID, e.CallerTokenID, e.AgentID, e.Username,
			time.Unix(e.CreatedAt, 0).Format(time.RFC3339))
	}
	return nil
}
