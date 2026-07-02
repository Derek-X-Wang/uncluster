//go:build windows

package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/derek-x-wang/uncluster/internal/gatekeeper"
)

// deprovisionCleanupHook returns the agent deprovision-cleanup hook for Windows:
// uninstall the LocalSystem UnclusterPrincipalsWriter service so it never
// outlives the agent (#127 invariant; #146). The CLI wires this into the agent
// (the agent package cannot import gatekeeper — that would be a cycle).
//
// It is best-effort at the agent's request: onRevoked logs a returned error and
// still completes deprovision. Runtime note: the low-priv agent account may lack
// service-control rights over the writer, in which case this returns
// access-denied and the writer must be removed by the operator's manual
// uninstall; real-Windows T2 is the definitive check.
func deprovisionCleanupHook() func(ctx context.Context) error {
	return func(ctx context.Context) error {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolve executable for writer uninstall: %w", err)
		}
		return gatekeeper.UninstallPrincipalsWriterService(ctx, exe)
	}
}
