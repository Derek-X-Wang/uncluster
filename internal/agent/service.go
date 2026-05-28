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
