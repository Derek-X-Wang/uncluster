package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/agent"
	"github.com/derek-x-wang/uncluster/internal/api"
)

// newServerUpdateCmd returns the `uncluster server update` command group.
func newServerUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Manage agent update policy",
	}

	var (
		version    string
		assetTmpl  string
		sha256Tmpl string
		force      bool
	)

	set := &cobra.Command{
		Use:   "set",
		Short: "Set the expected agent version (triggers automatic agent self-update)",
		Long: `Set the expected agent version on the control plane. On the next heartbeat
any agent whose agent_version differs from expected_version will receive a
check_update command and will download+verify+swap the new binary.

The asset-url-template and sha256-url-template accept {os}, {arch}, and
{version} as substitution variables. Example:

  --asset-url-template=https://github.com/Derek-X-Wang/uncluster/releases/download/{version}/uncluster_{os}_{arch}
  --sha256-url-template=https://github.com/Derek-X-Wang/uncluster/releases/download/{version}/uncluster_{os}_{arch}.sha256`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if version == "" {
				return fmt.Errorf("--version is required")
			}
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			client := NewClient(cfg.Server, cfg.Token)
			req := api.SetUpdatePolicyRequest{
				ExpectedVersion:   version,
				AssetURLTemplate:  assetTmpl,
				SHA256URLTemplate: sha256Tmpl,
				Force:             force,
			}
			if err := client.Do(cmd.Context(), "POST", "/v1/server/update", req, nil); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "update policy set: expected_version=%s\n", version)
			return nil
		},
	}
	set.Flags().StringVar(&version, "version", "", "expected agent version, e.g. v2.1.0 (required)")
	set.Flags().StringVar(&assetTmpl, "asset-url-template", "", "URL template for binary asset ({os}, {arch}, {version})")
	set.Flags().StringVar(&sha256Tmpl, "sha256-url-template", "", "URL template for SHA256 checksum file")
	set.Flags().BoolVar(&force, "force", false, "force update even if agent already reports the expected version")
	cmd.AddCommand(set)

	return cmd
}

// newAgentUpdateCmd returns the `uncluster agent update` command.
func newAgentUpdateCmd() *cobra.Command {
	var (
		pin   string
		unpin bool
	)
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Pin or unpin the local agent version (overrides server's expected_version)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if pin != "" && unpin {
				return fmt.Errorf("--pin and --unpin are mutually exclusive")
			}
			cfgPath, err := agent.DefaultConfigPath()
			if err != nil {
				return err
			}
			cfg, err := agent.LoadConfig(cfgPath)
			if err != nil {
				return fmt.Errorf("load agent config: %w", err)
			}
			switch {
			case unpin:
				cfg.PinnedVersion = ""
				if err := agent.SaveConfig(cfgPath, cfg); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "version pin cleared — agent will follow server's expected_version")
			case pin != "":
				cfg.PinnedVersion = pin
				if err := agent.SaveConfig(cfgPath, cfg); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "version pinned to %s — agent will not update until unpinned\n", pin)
			default:
				// Print current pin state.
				if cfg.PinnedVersion == "" {
					fmt.Fprintln(cmd.OutOrStdout(), "no version pin set (following server's expected_version)")
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "pinned to %s\n", cfg.PinnedVersion)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&pin, "pin", "", "pin agent to this version, e.g. v2.0.0")
	cmd.Flags().BoolVar(&unpin, "unpin", false, "clear the local version pin")
	return cmd
}

// newAgentRollbackCmd returns the `uncluster agent rollback` command.
func newAgentRollbackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rollback",
		Short: "Swap binary.prev back into place (revert the last self-update)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfgPath, err := agent.DefaultConfigPath()
			if err != nil {
				return err
			}
			if _, err := agent.LoadConfig(cfgPath); err != nil {
				return fmt.Errorf("load agent config: %w", err)
			}
			updater := agent.NewUpdater("", "", nil)
			if err := updater.Rollback(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "rollback complete — restart the agent service to apply")
			return nil
		},
	}
}
