package api

import "testing"

// TestExpectedPathsFor_Golden pins the canonical SSH artifact paths per OS. These
// values are the single source of truth consumed by the Control plane's
// expected_paths response, the Gatekeeper installer, the Windows principals
// writer, and doctor (#145). They must not change — the install and e2e tests,
// and every enrolled Agent's on-disk layout, depend on these exact strings.
func TestExpectedPathsFor_Golden(t *testing.T) {
	windows := ExpectedPaths{
		CAPubkey:      `C:\ProgramData\ssh\uncluster_ca.pub`,
		SSHDropIn:     `C:\ProgramData\ssh\sshd_config.d\uncluster.conf`,
		PrincipalsDir: `C:\ProgramData\ssh\auth_principals`,
	}
	posix := ExpectedPaths{
		CAPubkey:      "/etc/ssh/uncluster_ca.pub",
		SSHDropIn:     "/etc/ssh/sshd_config.d/uncluster.conf",
		PrincipalsDir: "/etc/ssh/auth_principals",
	}

	cases := []struct {
		goos string
		want ExpectedPaths
	}{
		{"windows", windows},
		{"linux", posix},
		{"darwin", posix},
		{"", posix},      // unknown/empty → POSIX default
		{"plan9", posix}, // any other → POSIX default
	}
	for _, tc := range cases {
		if got := ExpectedPathsFor(tc.goos); got != tc.want {
			t.Errorf("ExpectedPathsFor(%q) = %+v, want %+v", tc.goos, got, tc.want)
		}
	}
}

// TestPathConsts_ConsistentWithStruct guards the exported per-artifact consts
// against drifting from the struct builder — every consumer that references a
// single const (e.g. the Windows writer's WindowsPrincipalsDirPath) must get the
// same value ExpectedPathsFor returns.
func TestPathConsts_ConsistentWithStruct(t *testing.T) {
	win := ExpectedPathsFor("windows")
	if WindowsCAPubkeyPath != win.CAPubkey ||
		WindowsSSHDropInPath != win.SSHDropIn ||
		WindowsPrincipalsDirPath != win.PrincipalsDir {
		t.Errorf("windows consts drift from ExpectedPathsFor(\"windows\") = %+v", win)
	}
	posix := ExpectedPathsFor("linux")
	if POSIXCAPubkeyPath != posix.CAPubkey ||
		POSIXSSHDropInPath != posix.SSHDropIn ||
		POSIXPrincipalsDirPath != posix.PrincipalsDir {
		t.Errorf("posix consts drift from ExpectedPathsFor(\"linux\") = %+v", posix)
	}
}
