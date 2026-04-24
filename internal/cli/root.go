package cli

import (
	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/version"
)

// NewRoot returns the root cobra command.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "uncluster",
		Short:         "Uncluster — a lightweight personal compute layer",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	// Subcommands are attached in later phases.
	return root
}
