//go:build windows

package engine

import (
	"net"
	"os/exec"
	"regexp"
	"syscall"
)

// routeLine matches the IPv4 default-route rows of `route print -4`:
//
//	0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.74     25
//
// Group 1 is the gateway, group 2 the local interface address.
var routeLine = regexp.MustCompile(`(?m)^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})`)

func defaultGateway(selfIP net.IP, ifname string) (net.IP, error) {
	cmd := exec.Command("route", "print", "-4")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return nil, errNoGateway
	}

	var fallback net.IP
	for _, m := range routeLine.FindAllStringSubmatch(string(out), -1) {
		gw := net.ParseIP(m[1]).To4()
		if gw == nil || gw.IsUnspecified() {
			continue
		}
		ifaceIP := net.ParseIP(m[2]).To4()
		if ifaceIP != nil && ifaceIP.Equal(selfIP) {
			return gw, nil
		}
		if fallback == nil {
			fallback = gw
		}
	}
	if fallback == nil {
		return nil, errNoGateway
	}
	return fallback, nil
}
