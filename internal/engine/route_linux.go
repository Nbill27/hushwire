//go:build linux

package engine

import (
	"net"
	"os"
	"strconv"
	"strings"
)

// /proc/net/route columns:
// Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
// Destination 00000000 means the default route; Gateway is little-endian hex.
func defaultGateway(selfIP net.IP, ifname string) (net.IP, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, errNoGateway
	}
	var fallback net.IP
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 || f[1] != "00000000" {
			continue
		}
		gw, err := hexLE(f[2])
		if err != nil || gw.IsUnspecified() {
			continue
		}
		if f[0] == ifname {
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

func hexLE(s string) (net.IP, error) {
	if len(s) != 8 {
		return nil, errNoGateway
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return nil, err
	}
	return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)), nil
}
