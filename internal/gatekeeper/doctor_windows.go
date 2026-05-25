//go:build windows

package gatekeeper

import (
	"context"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

// Doctor is not implemented on Windows. Returns a single failure result.
func Doctor(_ context.Context, _ agent.Config) DoctorResults {
	return DoctorResults{
		{Name: "platform", Status: CheckFail,
			Message: "doctor not implemented on Windows (see issue #8, S9a)"},
	}
}
