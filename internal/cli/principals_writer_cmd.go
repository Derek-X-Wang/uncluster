package cli

import (
	"github.com/spf13/cobra"
)

// newPrincipalsWriterCmd builds the hidden `uncluster principals-writer`
// command group. It is the binding for the LocalSystem UnclusterPrincipalsWriter
// SCM service introduced for the #127 role-split: the service unit's
// BinaryPathName is `<exe> principals-writer run`, and SCM dispatches the
// long-running writer loop through it.
//
// Hidden because it is an internal service entry point, never an operator
// command — operators interact via `uncluster acl ...` and `uncluster agent
// ...`; the writer is plumbing the installer wires up. It is registered on all
// platforms (so argv detection under SCM is uniform), but the run subcommand
// only does real work on Windows (RunPrincipalsWriter is a build-tagged no-op
// erroring on non-Windows).
func newPrincipalsWriterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "principals-writer",
		Short:  "Internal: LocalSystem AuthorizedPrincipalsFile writer service (Windows)",
		Hidden: true,
	}
	run := &cobra.Command{
		Use:   "run",
		Short: "Run the principals-writer in the foreground (used by the SCM service unit)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return RunPrincipalsWriter(cmd.Context(), cmd.ErrOrStderr())
		},
	}
	cmd.AddCommand(run)
	return cmd
}
