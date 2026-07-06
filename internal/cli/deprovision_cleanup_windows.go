//go:build windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/derek-x-wang/uncluster/internal/gatekeeper"
)

// deprovisionCleanupHook returns the agent deprovision-cleanup hook for Windows:
//   - remove the uncluster-managed directive block from the base sshd_config so
//     deprovision leaves the host's sshd config as it found it (#179); and
//   - uninstall the LocalSystem UnclusterPrincipalsWriter service so it never
//     outlives the agent (#127 invariant; #146).
//
// The CLI wires this into the agent (the agent package cannot import gatekeeper —
// that would be a cycle). Both steps are best-effort at the agent's request:
// onRevoked logs a returned error and still completes deprovision. Runtime note:
// the low-priv agent account may lack service-control rights over the writer (and
// write access to the base sshd_config), in which case this returns access-denied
// and the operator's manual uninstall completes cleanup; real-Windows T2 is the
// definitive check.
func deprovisionCleanupHook() func(ctx context.Context) error {
	return func(ctx context.Context) error {
		var errs []error
		if err := gatekeeper.RemoveWindowsManagedDirectives(); err != nil {
			errs = append(errs, fmt.Errorf("remove sshd directives: %w", err))
		}
		exe, err := os.Executable()
		if err != nil {
			errs = append(errs, fmt.Errorf("resolve executable for writer uninstall: %w", err))
		} else if err := gatekeeper.UninstallPrincipalsWriterService(ctx, exe); err != nil {
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}
}
