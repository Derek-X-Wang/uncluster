//go:build windows

package gatekeeper

import (
	"github.com/kardianos/service"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// windowsServiceAccountName is the Windows virtual account for the service.
// Windows derives a service's virtual account as NT SERVICE\<ServiceName>, so
// this is built from agent.WindowsServiceName to stay in lockstep with it.
// The account has limited privileges and is the preferred choice.
const windowsServiceAccountName = `NT SERVICE\` + agent.WindowsServiceName

// buildService constructs a kardianos/service.Service for Windows SCM.
func buildService(cfg agent.Config, serviceExe string) (service.Service, error) {
	svcCfg := &service.Config{
		Name:        agent.WindowsServiceName,
		DisplayName: "Uncluster Agent",
		Description: "Uncluster node agent (SSH certificate gatekeeper)",
		Executable:  serviceExe,
		Arguments:   []string{"agent", "run"},
		// Virtual account — no password needed; SCM manages credentials.
		UserName: windowsServiceAccountName,
	}
	prg := &agentSvcProgram{}
	return service.New(prg, svcCfg)
}

// agentSvcProgram satisfies service.Interface. On Windows it is only
// passed to service.New so kardianos can construct the install metadata
// (it requires a non-nil program even for install-only use). The runtime
// SCM control-handler handshake is owned by cmd/uncluster/agent_run_windows.go's
// svc.Run path — NOT by this program — because kardianos's stub Start/Stop
// reports nothing to SCM, which made `net start` time out after 30s
// before #88. Keep this struct as a no-op so svc.Install/Uninstall continue
// to work; never expect Start/Stop to be called at runtime on Windows.
type agentSvcProgram struct{}

func (p *agentSvcProgram) Start(service.Service) error { return nil }
func (p *agentSvcProgram) Stop(service.Service) error  { return nil }
