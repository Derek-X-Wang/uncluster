package agent

import (
	"net"
	"os/exec"
	"strings"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// DetectEndpoints auto-detects the agent's network endpoints:
//   - "home-tailnet" → first Tailscale IPv4 from `tailscale ip -4`
//   - "home-lan"     → first non-loopback, non-link-local IPv4 on a non-loopback interface
//
// Explicit overrides in the form "<subnet>@<address>" are merged in, replacing
// any auto-detected entry for that subnet. Use "<subnet>@" to remove an entry.
func DetectEndpoints(overrides []string) []api.AgentEndpoint {
	result := map[string]string{} // subnet → address

	// Auto-detect Tailscale.
	if ip := tailscaleIP(); ip != "" {
		result["home-tailnet"] = ip
	}

	// Auto-detect LAN.
	if ip := defaultLANIP(); ip != "" {
		result["home-lan"] = ip
	}

	// Apply overrides.
	for _, o := range overrides {
		parts := strings.SplitN(o, "@", 2)
		if len(parts) != 2 {
			continue
		}
		subnet, addr := parts[0], parts[1]
		if addr == "" {
			delete(result, subnet)
		} else {
			result[subnet] = addr
		}
	}

	endpoints := make([]api.AgentEndpoint, 0, len(result))
	for subnet, addr := range result {
		endpoints = append(endpoints, api.AgentEndpoint{Subnet: subnet, Address: addr})
	}
	return endpoints
}

// tailscaleIP runs `tailscale ip -4` and returns the first IPv4 Tailscale
// address. Returns empty string if tailscale is not installed or not connected.
func tailscaleIP() string {
	bin, err := exec.LookPath("tailscale")
	if err != nil {
		return ""
	}
	out, err := exec.Command(bin, "ip", "-4").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if ip := net.ParseIP(line); ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

// defaultLANIP returns the first non-loopback, non-link-local IPv4 address
// on a non-loopback interface.
func defaultLANIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	return ""
}
