package engine

import (
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

var (
	broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	zeroMAC      = net.HardwareAddr{0, 0, 0, 0, 0, 0}
)

func serialize(ls ...gopacket.SerializableLayer) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// arpRequestBytes builds a broadcast ARP "who-has dstIP".
func arpRequestBytes(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       broadcastMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      zeroMAC,
		DstProtAddress:    dstIP.To4(),
	}
	return serialize(eth, arp)
}

// arpReplyBytes builds a unicast ARP reply. ethSrc is the Ethernet source
// address (normally our own NIC MAC); senderMAC/senderIP are the values the
// receiver will cache.
func arpReplyBytes(ethSrc, senderMAC net.HardwareAddr, senderIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       ethSrc,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   senderMAC,
		SourceProtAddress: senderIP.To4(),
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstIP.To4(),
	}
	return serialize(eth, arp)
}

// probe sends ARP requests for the given IPs and collects replies until the
// timeout elapses.
func (e *Engine) probe(ips []net.IP, timeout time.Duration) (map[string]net.HardwareAddr, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	e.scanMu.Lock()
	defer e.scanMu.Unlock()
	h, err := pcap.OpenLive(e.PcapName, 65536, false, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", e.PcapName, err)
	}
	defer h.Close()
	if err := h.SetBPFFilter("arp"); err != nil {
		return nil, fmt.Errorf("bpf arp: %w", err)
	}

	for _, ip := range ips {
		if ip == nil || ip.Equal(e.SelfIP) {
			continue
		}
		pkt, err := arpRequestBytes(e.SelfMAC, e.SelfIP, ip)
		if err != nil {
			return nil, err
		}
		if err := h.WritePacketData(pkt); err != nil {
			return nil, fmt.Errorf("send arp to %s: %w", ip, err)
		}
	}

	res := make(map[string]net.HardwareAddr)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, _, err := h.ReadPacketData()
		if err != nil {
			continue
		}
		ip, mac, ok := parseARPReply(data)
		if !ok || ip.Equal(e.SelfIP) {
			continue
		}
		res[ip.String()] = mac
	}
	return res, nil
}

func parseARPReply(data []byte) (net.IP, net.HardwareAddr, bool) {
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	l := pkt.Layer(layers.LayerTypeARP)
	if l == nil {
		return nil, nil, false
	}
	arp, ok := l.(*layers.ARP)
	if !ok || arp.Operation != layers.ARPReply {
		return nil, nil, false
	}
	ip := make(net.IP, 4)
	copy(ip, arp.SourceProtAddress)
	mac := make(net.HardwareAddr, 6)
	copy(mac, arp.SourceHwAddress)
	return ip, mac, true
}

// Scan sweeps the subnet with ARP requests and returns every host that
// answered.
func (e *Engine) Scan(timeout time.Duration) ([]Device, error) {
	if e.CIDR == nil {
		return nil, fmt.Errorf("no CIDR configured")
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	e.scanMu.Lock()
	defer e.scanMu.Unlock()
	h, err := pcap.OpenLive(e.PcapName, 65536, false, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", e.PcapName, err)
	}
	defer h.Close()
	if err := h.SetBPFFilter("arp"); err != nil {
		return nil, fmt.Errorf("bpf arp: %w", err)
	}

	for _, ip := range Hosts(e.CIDR) {
		if ip.Equal(e.SelfIP) {
			continue
		}
		pkt, err := arpRequestBytes(e.SelfMAC, e.SelfIP, ip)
		if err != nil {
			return nil, err
		}
		if err := h.WritePacketData(pkt); err != nil {
			return nil, fmt.Errorf("send arp to %s: %w", ip, err)
		}
	}

	found := make(map[string]*Device)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, ci, err := h.ReadPacketData()
		if err != nil {
			continue
		}
		ip, mac, ok := parseARPReply(data)
		if !ok || ip.Equal(e.SelfIP) {
			continue
		}
		key := ip.String()
		d, ok := found[key]
		if !ok {
			d = &Device{IP: ip, MAC: mac}
			found[key] = d
		}
		if ci.Timestamp.After(d.LastSeen) {
			d.LastSeen = ci.Timestamp
		}
	}

	out := make([]Device, 0, len(found))
	for _, d := range found {
		d.Vendor = e.OUI.Lookup(d.MAC.String())
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		return ipToU32(out[i].IP) < ipToU32(out[j].IP)
	})
	return out, nil
}

func ipToU32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}
