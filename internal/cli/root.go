package cli

import (
	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/version"
)

// NewRoot returns the root cobra command.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "uncluster",
		Short:         "Uncluster — SSH certificate-authority compute gateway",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newServerCmd())
	root.AddCommand(newConfigCmd())
	root.AddCommand(newAgentCmd())
	root.AddCommand(newACLCmd())
	root.AddCommand(newSSHCmd())
	root.AddCommand(newAgentsCmd())
	root.AddCommand(newAuditCmd())
	root.AddCommand(newValidateCmd())
	return root
}
