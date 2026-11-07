package engine

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket/pcap"
)

var errNoGateway = errors.New("default gateway not found")

// Device is one host observed on the local L2 segment.
type Device struct {
	IP       net.IP
	MAC      net.HardwareAddr
	Vendor   string
	LastSeen time.Time
}

// Engine binds every raw-socket operation to a single interface.
type Engine struct {
	Iface      *net.Interface
	PcapName   string
	SelfIP     net.IP
	SelfMAC    net.HardwareAddr
	GatewayIP  net.IP
	GatewayMAC net.HardwareAddr
	CIDR       *net.IPNet
	OUI        *OUITable

	// scanMu serializes sweeps: the UI scan and the watchdog must not open
	// competing pcap handles or interleave ARP requests on the same segment.
	scanMu sync.Mutex
}

// Open resolves the interface, its pcap device name, the gateway and the
// gateway MAC. Everything needed to start poisoning.
func Open(ifaceName, ouiPath string) (*Engine, error) {
	ifi, err := pickIface(ifaceName)
	if err != nil {
		return nil, err
	}
	selfIP, cidr := ifaceIPv4(ifi)
	if selfIP == nil {
		return nil, fmt.Errorf("interface %s has no usable IPv4 address", ifi.Name)
	}
	pcapName, err := pcapDeviceFor(ifi, selfIP)
	if err != nil {
		return nil, err
	}

	e := &Engine{
		Iface:    ifi,
		PcapName: pcapName,
		SelfIP:   selfIP,
		SelfMAC:  ifi.HardwareAddr,
		CIDR:     cidr,
		OUI:      LoadOUI(ouiPath),
	}

	gw, err := defaultGateway(selfIP, ifi.Name)
	if err != nil || gw == nil || gw.IsUnspecified() {
		gw = fallbackGateway(cidr)
	}
	e.GatewayIP = gw

	if mac, err := e.ResolveMAC(gw, 2*time.Second); err == nil {
		e.GatewayMAC = mac
	}
	return e, nil
}

// ResolveMAC does a single ARP probe for one IP.
func (e *Engine) ResolveMAC(ip net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	found, err := e.probe([]net.IP{ip}, timeout)
	if err != nil {
		return nil, err
	}
	mac, ok := found[ip.String()]
	if !ok {
		return nil, fmt.Errorf("no ARP reply from %s", ip)
	}
	return mac, nil
}

func pickIface(name string) (*net.Interface, error) {
	if name != "" {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w", name, err)
		}
		return ifi, nil
	}
	ifis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var fallback *net.Interface
	for i := range ifis {
		ifi := &ifis[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(ifi.HardwareAddr) != 6 {
			continue
		}
		ip, _ := ifaceIPv4(ifi)
		if ip == nil {
			continue
		}
		if fallback == nil {
			fallback = ifi
		}
		if ifi.Flags&net.FlagBroadcast != 0 {
			return ifi, nil
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, errors.New("no usable IPv4 interface found")
}

func ifaceIPv4(ifi *net.Interface) (net.IP, *net.IPNet) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, nil
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		v4 := ipn.IP.To4()
		if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
			continue
		}
		ones, bits := ipn.Mask.Size()
		if bits == 128 {
			ones, bits = net.IPMask(ipn.Mask[12:]).Size()
		}
		if bits != 32 {
			continue
		}
		mask := net.CIDRMask(ones, 32)
		// CIDR must hold the network address, not the host address, or
		// Hosts() would enumerate from the host and overflow the subnet.
		return v4, &net.IPNet{IP: v4.Mask(mask), Mask: mask}
	}
	return nil, nil
}

func pcapDeviceFor(ifi *net.Interface, selfIP net.IP) (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("pcap device enumeration: %w", err)
	}
	for _, d := range devs {
		for _, a := range d.Addresses {
			if a.IP.Equal(selfIP) {
				return d.Name, nil
			}
		}
	}
	low := strings.ToLower(ifi.Name)
	for _, d := range devs {
		if strings.Contains(strings.ToLower(d.Name), low) {
			return d.Name, nil
		}
	}
	for _, d := range devs {
		if strings.Contains(strings.ToLower(d.Description), low) {
			return d.Name, nil
		}
	}
	return "", fmt.Errorf("no pcap device matching interface %s (is Npcap installed?)", ifi.Name)
}

func fallbackGateway(cidr *net.IPNet) net.IP {
	if cidr == nil {
		return nil
	}
	base := cidr.IP.To4()
	if base == nil {
		return nil
	}
	gw := make(net.IP, 4)
	copy(gw, base)
	gw[3]++
	return gw
}

// Hosts enumerates every usable host address in a subnet.
func Hosts(cidr *net.IPNet) []net.IP {
	base := cidr.IP.To4()
	if base == nil {
		return nil
	}
	ones, bits := cidr.Mask.Size()
	if bits != 32 {
		return nil
	}
	total := 1 << uint(32-ones)
	if total > 65536 {
		total = 65536
	}
	out := make([]net.IP, 0, total)
	start := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	for i := 1; i < total-1; i++ {
		v := start + uint32(i)
		out = append(out, net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)))
	}
	return out
}
