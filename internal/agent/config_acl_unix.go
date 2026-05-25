//go:build !windows

package agent

// restrictConfigACL on Unix is a no-op — mode 0600 is applied at write time
// in SaveConfig via OpenFile with perm 0o600.
func restrictConfigACL(_ string) error { return nil }
