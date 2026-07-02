//go:build !windows

package cli

import "context"

// deprovisionCleanupHook returns nil on non-Windows platforms: Unix/macOS have
// no separate LocalSystem principals-writer service to tear down (the low-priv
// service account wipes principals in-process on deprovision), so onRevoked's
// behavior is unchanged (#146).
func deprovisionCleanupHook() func(ctx context.Context) error {
	return nil
}
