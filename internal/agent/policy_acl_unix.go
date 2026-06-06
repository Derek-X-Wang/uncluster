//go:build !windows

package agent

// restrictPrincipalsFileACL on Unix is a no-op. The per-user principals file's
// safety is governed by the principals directory ownership/mode set at install
// time (root:<service account>, 0775 dir / 0644 files) plus sshd's own
// StrictModes check, which on Unix accepts a root-owned, group-writable-by-the-
// service-account file. The Windows path needs an explicit per-file DACL because
// Win32-OpenSSH's auth2-pubkeyfile.c rejects any file carrying a writable ACE
// for a non-admin/non-SYSTEM principal (#127).
func restrictPrincipalsFileACL(_ string) error { return nil }
