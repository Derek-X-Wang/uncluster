//go:build windows

package gatekeeper

import (
	"github.com/kardianos/service"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// windowsServiceAccountName is the Windows virtual account for the service.
// NT SERVICE\UnclusterAgent has limited privileges and is the preferred choice.
const windowsServiceAccountName = `NT SERVICE\UnclusterAgent`

// buildService constructs a kardianos/service.Service for Windows SCM.
func buildService(cfg agent.Config, serviceExe string) (service.Service, error) {
	svcCfg := &service.Config{
		Name:        "UnclusterAgent",
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

// agentSvcProgram satisfies service.Interface. The agent logic runs via the
// uncluster agent run sub-process; this program is a no-op shell used only
// when kardianos/service needs to call Start/Stop directly.
type agentSvcProgram struct{}

func (p *agentSvcProgram) Start(service.Service) error { return nil }
func (p *agentSvcProgram) Stop(service.Service) error  { return nil }
