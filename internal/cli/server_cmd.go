package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

func newServerCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "server", Short: "Run and manage the Uncluster control plane"}

	var addr, dbPath string
	start := &cobra.Command{
		Use:   "start",
		Short: "Start the control plane",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if dbPath == "" {
				dir := os.Getenv("XDG_DATA_HOME")
				if dir == "" {
					home, _ := os.UserHomeDir()
					dir = filepath.Join(home, ".local", "share")
				}
				_ = os.MkdirAll(filepath.Join(dir, "uncluster"), 0o700)
				dbPath = filepath.Join(dir, "uncluster", "uncluster.db")
			}
			st, err := store.OpenSQLite(dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer st.Close()

			srv := server.New(server.Config{Store: st})
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			return srv.Start(ctx, addr)
		},
	}
	start.Flags().StringVar(&addr, "addr", ":7777", "listen address")
	start.Flags().StringVar(&dbPath, "db", "", "sqlite db path (default: $XDG_DATA_HOME/uncluster/uncluster.db)")
	cmd.AddCommand(start)

	// token subcommands — uses the HTTP API; needs server+cli-token config.
	tok := &cobra.Command{Use: "token", Short: "Manage tokens (on a running server)"}

	var kind, label string
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a token (join or cli). Prints plaintext ONCE.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")
			}
			client := NewClient(cfg.Server, cfg.Token)
			var out api.CreateTokenResponse
			if err := client.Do(cmd.Context(), "POST", "/v1/tokens",
				api.CreateTokenRequest{Kind: kind, Label: label}, &out); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "token: %s\n", out.Token)
			fmt.Fprintf(cmd.OutOrStdout(), "id:    %s\n", out.ID)
			return nil
		},
	}
	create.Flags().StringVar(&kind, "kind", "", "join | cli (required)")
	create.Flags().StringVar(&label, "label", "", "human-readable note")
	_ = create.MarkFlagRequired("kind")
	tok.AddCommand(create)

	ls := &cobra.Command{
		Use:   "ls",
		Short: "List tokens",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _ := LoadCLIConfig()
			client := NewClient(cfg.Server, cfg.Token)
			var out []api.TokenSummary
			if err := client.Do(cmd.Context(), "GET", "/v1/tokens", nil, &out); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%-18s %-6s %-20s %-10s\n", "ID", "KIND", "LABEL", "STATE")
			for _, t := range out {
				state := "active"
				switch {
				case t.RevokedAt != nil:
					state = "revoked"
				case t.UsedAt != nil:
					state = "used"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-18s %-6s %-20s %-10s\n", t.ID, t.Kind, t.Label, state)
			}
			return nil
		},
	}
	tok.AddCommand(ls)

	revoke := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke a token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := LoadCLIConfig()
			client := NewClient(cfg.Server, cfg.Token)
			return client.Do(cmd.Context(), "DELETE", "/v1/tokens/"+args[0], nil, nil)
		},
	}
	tok.AddCommand(revoke)

	cmd.AddCommand(tok)

	var bsLabel string
	bootstrap := &cobra.Command{
		Use:   "bootstrap",
		Short: "Mint the first CLI token by writing directly to the DB. Use only once per install.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := dbPath
			if path == "" {
				dir := os.Getenv("XDG_DATA_HOME")
				if dir == "" {
					home, _ := os.UserHomeDir()
					dir = filepath.Join(home, ".local", "share")
				}
				_ = os.MkdirAll(filepath.Join(dir, "uncluster"), 0o700)
				path = filepath.Join(dir, "uncluster", "uncluster.db")
			}
			st, err := store.OpenSQLite(path)
			if err != nil {
				return err
			}
			defer st.Close()

			tkn, err := token.Generate(token.KindCLI)
			if err != nil {
				return err
			}
			hash, err := token.HashSecret(tkn.Secret)
			if err != nil {
				return err
			}
			row, err := st.CreateToken(cmd.Context(), store.NewTokenParams{
				ID: tkn.ID, Kind: store.TokenCLI, SecretHash: hash, Label: bsLabel,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "token: %s\n", tkn.String())
			fmt.Fprintf(cmd.OutOrStdout(), "id:    %s\n", row.ID)
			fmt.Fprintln(cmd.OutOrStdout(), "(shown ONCE — copy it now)")
			return nil
		},
	}
	bootstrap.Flags().StringVar(&dbPath, "db", "", "sqlite db path (default: $XDG_DATA_HOME/uncluster/uncluster.db)")
	bootstrap.Flags().StringVar(&bsLabel, "label", "bootstrap", "label for the minted token")
	cmd.AddCommand(bootstrap)

	return cmd
}
