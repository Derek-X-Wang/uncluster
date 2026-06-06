package agent

// WindowsServiceName is the SCM service name the agent is installed and run
// under on Windows. Single source of truth, referenced by:
//   - the installer (internal/gatekeeper/{service,install,doctor}_windows.go)
//   - the self-update restart path (internal/agent/restart_windows.go)
//   - the SCM control handler (cmd/uncluster/agent_run_windows.go)
//
// A mismatch between the name SCM registers at install and the name the
// runtime svc.Run handler / restart commands use makes `net start` time out
// (the failure mode in #88, and the same drift class as the Linux systemd
// unit-name bug fixed in 113b747). Keep every reference pointed here.
const WindowsServiceName = "UnclusterAgent"

// WindowsPrincipalsWriterServiceName is the SCM service name of the LocalSystem
// principals-writer service introduced for the #127 role-split (ADR-0004
// Windows amendment). It runs as LocalSystem (so files it creates are
// SYSTEM-owned and accepted by Win32-OpenSSH without SeRestore), is network-
// less, and has its privileges stripped to the minimum via
// SERVICE_REQUIRED_PRIVILEGES at install. The low-priv UnclusterAgent service
// hands it validated desired-state over the spool; the writer is the only
// identity that ever writes an AuthorizedPrincipalsFile on Windows.
//
// Referenced by:
//   - the installer (internal/gatekeeper/install_windows.go) — registers it,
//     sets its required-privileges, removes the agent's auth_principals grant;
//   - the SCM control handler (cmd/uncluster/principals_writer_windows.go);
//   - the doctor (internal/gatekeeper/doctor_windows.go) — verifies it exists.
const WindowsPrincipalsWriterServiceName = "UnclusterPrincipalsWriter"
