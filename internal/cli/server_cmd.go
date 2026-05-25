package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/ca"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

func newServerCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "server", Short: "Run and manage the Uncluster control plane"}

	var addr, dbPath, caPath string
	start := &cobra.Command{
		Use:   "start",
		Short: "Start the control plane",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dbPath = resolveDBPath(dbPath)
			caPath = resolveCAPath(caPath)

			// If a CA file exists, verify mode before we accept any traffic.
			// Absent CA = warn but allow start (cert signing and enrollment CA
			// pubkey delivery simply won't work).
			var caPubkeyLine string
			var caSigner ssh.Signer
			caPubPath := caPath + ".pub"
			if _, err := os.Stat(caPath); err == nil {
				signer, err := ca.LoadPrivateFromDisk(caPath)
				if err != nil {
					return fmt.Errorf("ca check: %w", err)
				}
				caSigner = signer
				// Read the public key line to embed in enrollment responses.
				if b, err := os.ReadFile(caPubPath); err == nil {
					caPubkeyLine = strings.TrimSpace(string(b))
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("ca stat: %w", err)
			} else {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"warning: no CA key at %s — run `uncluster server bootstrap` before issuing certs\n", caPath)
			}

			st, err := store.OpenSQLite(dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer st.Close()

			srv := server.New(server.Config{Store: st, CAPubkey: caPubkeyLine, CASigner: caSigner})
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			return srv.Start(ctx, addr)
		},
	}
	start.Flags().StringVar(&addr, "addr", ":7777", "listen address")
	start.Flags().StringVar(&dbPath, "db", "", "sqlite db path (default: $XDG_DATA_HOME/uncluster/uncluster.db)")
	start.Flags().StringVar(&caPath, "ca", "", "CA private key path (default: $XDG_DATA_HOME/uncluster/ca)")
	cmd.AddCommand(start)

	// token subcommands — uses the HTTP API; needs server+cli-token config.
	tok := &cobra.Command{Use: "token", Short: "Manage tokens (on a running server)"}

	var kind, label string
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a token (join, cli, or caller). Prints plaintext ONCE.",
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
	create.Flags().StringVar(&kind, "kind", "", "join | cli | caller (required)")
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
			fmt.Fprintf(cmd.OutOrStdout(), "%-18s %-7s %-20s %-10s\n", "ID", "KIND", "LABEL", "STATE")
			for _, t := range out {
				state := "active"
				switch {
				case t.RevokedAt != nil:
					state = "revoked"
				case t.UsedAt != nil:
					state = "used"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-18s %-7s %-20s %-10s\n", t.ID, t.Kind, t.Label, state)
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

	// bootstrap — generates CA if missing + mints a fresh caller token.
	// Re-runnable: never overwrites the existing CA; each run mints a new token.
	var bsLabel, bsDBPath, bsCAPath string
	bootstrap := &cobra.Command{
		Use:   "bootstrap",
		Short: "Generate CA (if missing) and mint a caller token. Re-runnable; never overwrites CA.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			bsDBPath = resolveDBPath(bsDBPath)
			bsCAPath = resolveCAPath(bsCAPath)
			bsCAPubPath := bsCAPath + ".pub"

			// 1. CA: load existing or generate fresh.
			var caStatus string
			if _, err := os.Stat(bsCAPath); err == nil {
				if _, err := ca.LoadPrivateFromDisk(bsCAPath); err != nil {
					return fmt.Errorf("existing ca: %w", err)
				}
				caStatus = "kept existing"
			} else if errors.Is(err, os.ErrNotExist) {
				priv, pub, err := ca.Generate()
				if err != nil {
					return err
				}
				privBytes, err := ca.MarshalPrivate(priv)
				if err != nil {
					return err
				}
				pubBytes, err := ca.MarshalPublic(pub)
				if err != nil {
					return err
				}
				if err := ca.WritePrivateToDisk(bsCAPath, privBytes); err != nil {
					return err
				}
				if err := ca.WritePublicToDisk(bsCAPubPath, pubBytes); err != nil {
					return err
				}
				caStatus = "generated"
			} else {
				return fmt.Errorf("ca stat: %w", err)
			}

			// 2. DB: open (runs migrations).
			st, err := store.OpenSQLite(bsDBPath)
			if err != nil {
				return err
			}
			defer st.Close()

			// 3. Mint a caller token.
			tkn, err := token.Generate(token.KindCaller)
			if err != nil {
				return err
			}
			hash, err := token.HashSecret(tkn.Secret)
			if err != nil {
				return err
			}
			row, err := st.CreateToken(cmd.Context(), store.NewTokenParams{
				ID:         tkn.ID,
				Kind:       store.TokenCaller,
				SecretHash: hash,
				Label:      bsLabel,
			})
			if err != nil {
				return err
			}

			// 4. Report.
			pubBytes, _ := os.ReadFile(bsCAPubPath)
			fmt.Fprintln(cmd.OutOrStdout(), "[1/3] CA keypair                                 "+caStatus)
			fmt.Fprintln(cmd.OutOrStdout(), "[2/3] DB schema (migrations applied)            ok")
			fmt.Fprintln(cmd.OutOrStdout(), "[3/3] Minted caller token                        ok")
			fmt.Fprintln(cmd.OutOrStdout(), "")
			fmt.Fprintln(cmd.OutOrStdout(), "ca pubkey:")
			fmt.Fprintln(cmd.OutOrStdout(), "  "+string(pubBytes))
			fmt.Fprintf(cmd.OutOrStdout(), "caller token (shown ONCE — copy it now):\n  %s\n", tkn.String())
			fmt.Fprintf(cmd.OutOrStdout(), "id: %s\n", row.ID)
			return nil
		},
	}
	bootstrap.Flags().StringVar(&bsDBPath, "db", "", "sqlite db path (default: $XDG_DATA_HOME/uncluster/uncluster.db)")
	bootstrap.Flags().StringVar(&bsCAPath, "ca", "", "CA private key path (default: $XDG_DATA_HOME/uncluster/ca)")
	bootstrap.Flags().StringVar(&bsLabel, "label", "bootstrap", "label for the minted caller token")
	cmd.AddCommand(bootstrap)

	return cmd
}

// resolveDBPath returns the supplied path, or the XDG default if empty.
// Creates the parent directory.
func resolveDBPath(path string) string {
	if path != "" {
		return path
	}
	dir := os.Getenv("XDG_DATA_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".local", "share")
	}
	_ = os.MkdirAll(filepath.Join(dir, "uncluster"), 0o700)
	return filepath.Join(dir, "uncluster", "uncluster.db")
}

// resolveCAPath returns the supplied path, or the XDG default if empty.
// Does not create the parent (ca.WritePrivateToDisk handles that with 0700 mode).
func resolveCAPath(path string) string {
	if path != "" {
		return path
	}
	dir := os.Getenv("XDG_DATA_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dir, "uncluster", "ca")
}
