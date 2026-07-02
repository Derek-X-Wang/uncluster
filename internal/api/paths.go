package api

// Canonical SSH artifact paths — the SINGLE source of truth for where sshd reads
// the CA pubkey, the config drop-in, and the per-user principals files on each
// OS. The Control plane's expected_paths response, the Gatekeeper installer, the
// Windows LocalSystem principals writer, and doctor all resolve through these
// constants (via ExpectedPathsFor or by referencing a const directly), so a
// drift between "where sshd reads" and "where the writer writes" is a compile
// error rather than a silent, everything-reports-healthy login failure (#145).
//
// These live in package api because it is the lowest-level package all four
// consumers (server, gatekeeper, agent) already import, and it is the wire
// contract that carries these paths to the Agent at enrollment.
const (
	// Windows: everything lives under C:\ProgramData\ssh (Win32-OpenSSH's
	// __PROGRAMDATA__ base). The principals dir is owned by the LocalSystem
	// writer per the #127 role-split.
	WindowsCAPubkeyPath      = `C:\ProgramData\ssh\uncluster_ca.pub`
	WindowsSSHDropInPath     = `C:\ProgramData\ssh\sshd_config.d\uncluster.conf`
	WindowsPrincipalsDirPath = `C:\ProgramData\ssh\auth_principals`

	// POSIX (linux + darwin): everything lives under /etc/ssh.
	POSIXCAPubkeyPath      = "/etc/ssh/uncluster_ca.pub"
	POSIXSSHDropInPath     = "/etc/ssh/sshd_config.d/uncluster.conf"
	POSIXPrincipalsDirPath = "/etc/ssh/auth_principals"
)

// ExpectedPathsFor returns the canonical SSH paths for the given GOOS string.
// The Control plane calls this with the registering Agent's reported OS (which
// may differ from the Control plane's own OS), so selection is by string, not
// runtime.GOOS. Unknown or empty GOOS defaults to POSIX (linux, darwin, and
// anything else).
func ExpectedPathsFor(goos string) ExpectedPaths {
	if goos == "windows" {
		return ExpectedPaths{
			CAPubkey:      WindowsCAPubkeyPath,
			SSHDropIn:     WindowsSSHDropInPath,
			PrincipalsDir: WindowsPrincipalsDirPath,
		}
	}
	return ExpectedPaths{
		CAPubkey:      POSIXCAPubkeyPath,
		SSHDropIn:     POSIXSSHDropInPath,
		PrincipalsDir: POSIXPrincipalsDirPath,
	}
}
