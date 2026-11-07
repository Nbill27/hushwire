//go:build darwin

package engine

import (
	"net"
	"os/exec"
	"strings"
)

func defaultGateway(selfIP net.IP, ifname string) (net.IP, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return nil, errNoGateway
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "gateway:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		gw := net.ParseIP(v).To4()
		if gw != nil && !gw.IsUnspecified() {
			return gw, nil
		}
	}
	return nil, errNoGateway
}
