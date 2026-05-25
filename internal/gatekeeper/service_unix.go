//go:build !windows

package gatekeeper

import (
	"runtime"

	"github.com/kardianos/service"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// buildService constructs a kardianos/service.Service configured for system-
// level (not user-level) operation on macOS/Linux.
func buildService(cfg agent.Config, serviceExe string) (service.Service, error) {
	username := serviceAccountName()

	svcCfg := &service.Config{
		Name:        "com.uncluster.agent",
		DisplayName: "Uncluster Agent",
		Description: "Uncluster node agent (SSH certificate gatekeeper)",
		Executable:  serviceExe,
		Arguments:   []string{"agent", "run"},
		UserName:    username,
	}

	switch runtime.GOOS {
	case "darwin":
		svcCfg.Option = map[string]interface{}{
			"UserService": false, // system-level launchd plist in /Library/LaunchDaemons
		}
	default:
		// systemd unit — no extra options needed; UserName sets User= directive.
	}

	prg := &agentSvcProgram{}
	return service.New(prg, svcCfg)
}

// agentSvcProgram satisfies service.Interface. The actual agent logic runs
// via the `uncluster agent run` sub-process; the program here is a no-op
// shell used only when kardianos/service needs to call Start/Stop directly.
type agentSvcProgram struct{}

func (p *agentSvcProgram) Start(service.Service) error { return nil }
func (p *agentSvcProgram) Stop(service.Service) error  { return nil }
