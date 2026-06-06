//go:build !windows

package agent

// restrictPrincipalsFileACL on Unix is a no-op. A per-user principals file's
// safety is governed by the principals directory ownership/mode set at install
// time (root-owned dir, service-account write) plus sshd's StrictModes check,
// which on Unix accepts a root/service-owned file. Only Win32-OpenSSH needs an
// explicit per-file DACL, because it rejects any file carrying a write-class
// ACE for a non-admin/non-SYSTEM principal (#127); that lives in
// policy_acl_windows.go.
func restrictPrincipalsFileACL(_ string) error { return nil }
