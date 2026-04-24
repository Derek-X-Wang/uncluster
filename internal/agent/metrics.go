package agent

import (
	"runtime"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
)

func CollectMetrics() map[string]any {
	out := map[string]any{
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"cpu_cores":  runtime.NumCPU(),
		"go_version": runtime.Version(),
	}
	if info, err := host.Info(); err == nil {
		out["hostname"] = info.Hostname
		out["platform"] = info.Platform
		out["kernel"] = info.KernelVersion
		out["uptime_s"] = info.Uptime
	}
	if v, err := mem.VirtualMemory(); err == nil {
		out["mem_total"] = v.Total
		out["mem_available"] = v.Available
	}
	if pct, err := cpu.Percent(0, false); err == nil && len(pct) > 0 {
		out["cpu_pct"] = pct[0]
	}
	if l, err := load.Avg(); err == nil {
		out["load_1"] = l.Load1
		out["load_5"] = l.Load5
		out["load_15"] = l.Load15
	}
	return out
}
