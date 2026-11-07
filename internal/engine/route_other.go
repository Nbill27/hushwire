//go:build !windows && !linux && !darwin

package engine

import "net"

func defaultGateway(selfIP net.IP, ifname string) (net.IP, error) {
	return nil, errNoGateway
}
