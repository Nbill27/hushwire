package engine

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// CutInfo is the JSON-friendly view of one active cut.
type CutInfo struct {
	IP          string     `json:"ip"`
	MAC         string     `json:"mac"`
	Vendor      string     `json:"vendor"`
	Mode        string     `json:"mode"`
	Started     time.Time  `json:"started"`
	Expires     *time.Time `json:"expires,omitempty"`
	SecondsLeft int        `json:"secondsLeft"`
	Packets     uint64     `json:"packets"`
}

type cut struct {
	dev     Device
	mode    Mode
	started time.Time
	expires time.Time
	stop    chan struct{}
	stopOne sync.Once
	done    chan struct{}
	sent    atomic.Uint64
}

func (c *cut) info() CutInfo {
	ci := CutInfo{
		IP:      c.dev.IP.String(),
		MAC:     c.dev.MAC.String(),
		Vendor:  c.dev.Vendor,
		Mode:    string(c.mode),
		Started: c.started,
		Packets: c.sent.Load(),
	}
	if !c.expires.IsZero() {
		exp := c.expires
		ci.Expires = &exp
		left := int(time.Until(exp).Seconds())
		if left < 0 {
			left = 0
		}
		ci.SecondsLeft = left
	}
	return ci
}

// Manager owns every active cut and the shared log buffer.
type Manager struct {
	eng      *Engine
	logs     *LogBuffer
	interval time.Duration
	blocks   *BlockList

	mu   sync.Mutex
	cuts map[string]*cut
	wg   sync.WaitGroup
}

func NewManager(e *Engine, interval time.Duration) *Manager {
	if interval <= 0 {
		interval = 1500 * time.Millisecond
	}
	return &Manager{
		eng:      e,
		logs:     NewLogBuffer(600),
		interval: interval,
		cuts:     make(map[string]*cut),
	}
}

func (m *Manager) Engine() *Engine         { return m.eng }
func (m *Manager) Logs() *LogBuffer        { return m.logs }
func (m *Manager) Interval() time.Duration { return m.interval }

// UseBlocks attaches the MAC-keyed watch list. Until this is called the
// watchdog is inert, so a headless run never pays for it.
func (m *Manager) UseBlocks(bl *BlockList) { m.blocks = bl }

// Blocks returns the attached watch list, nil when there is none.
func (m *Manager) Blocks() *BlockList { return m.blocks }

// Scan proxies the engine sweep and logs the outcome.
func (m *Manager) Scan(timeout time.Duration) ([]Device, error) {
	m.logs.Add("info", "scan started on %s", m.eng.CIDR)
	devs, err := m.eng.Scan(timeout)
	if err != nil {
		m.logs.Add("error", "scan failed: %v", err)
		return nil, err
	}
	m.logs.Add("info", "scan finished: %d host(s)", len(devs))
	return devs, nil
}

// Start begins poisoning one device.
func (m *Manager) Start(dev Device, mode Mode, duration time.Duration) (CutInfo, error) {
	if dev.IP == nil || len(dev.MAC) != 6 {
		return CutInfo{}, errors.New("target needs both an IP and a MAC")
	}
	if dev.IP.Equal(m.eng.SelfIP) {
		return CutInfo{}, errors.New("refusing to cut this host")
	}
	if m.eng.GatewayIP != nil && dev.IP.Equal(m.eng.GatewayIP) {
		return CutInfo{}, errors.New("refusing to cut the gateway")
	}
	if !m.eng.GatewayReachable() {
		return CutInfo{}, fmt.Errorf("gateway MAC unknown (%v)", m.eng.GatewayIP)
	}
	if mode == "" {
		mode = ModeGateway
	}
	if mode != ModeGateway && mode != ModeBoth {
		return CutInfo{}, fmt.Errorf("unknown mode %q", mode)
	}

	key := dev.IP.String()
	mac := dev.MAC.String()
	// A device that moved to a new lease must not stay poisoned at its old
	// address; release the stale cut before claiming the new one.
	if stale := m.cutAtOtherIP(mac, key); stale != "" {
		if err := m.Stop(stale); err == nil {
			m.logs.Add("info", "released stale cut %s for %s", stale, mac)
		}
	}
	m.mu.Lock()
	if _, exists := m.cuts[key]; exists {
		m.mu.Unlock()
		return CutInfo{}, fmt.Errorf("%s is already cut", key)
	}
	c := &cut{
		dev:     dev,
		mode:    mode,
		started: time.Now(),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	if duration > 0 {
		c.expires = c.started.Add(duration)
	}
	m.cuts[key] = c
	m.mu.Unlock()

	m.wg.Add(1)
	go m.run(c)
	return c.info(), nil
}

func (m *Manager) run(c *cut) {
	key := c.dev.IP.String()
	defer m.wg.Done()
	defer close(c.done)
	defer func() {
		m.mu.Lock()
		if m.cuts[key] == c {
			delete(m.cuts, key)
		}
		m.mu.Unlock()
	}()

	s, err := m.eng.openSender()
	if err != nil {
		m.logs.Add("error", "cut %s: %v", key, err)
		return
	}
	defer s.Close()

	frames, err := m.eng.poisonFrames(c.dev, c.mode)
	if err != nil {
		m.logs.Add("error", "cut %s: %v", key, err)
		return
	}

	var deadline <-chan time.Time
	if !c.expires.IsZero() {
		tm := time.NewTimer(time.Until(c.expires))
		defer tm.Stop()
		deadline = tm.C
	}

	m.logs.Add("info", "cut %s (%s) mode=%s", key, c.dev.MAC, c.mode)
	tick := time.NewTicker(m.interval)
	defer tick.Stop()

	for {
		if err := s.send(frames); err != nil {
			m.logs.Add("error", "send to %s: %v", key, err)
		} else {
			c.sent.Add(uint64(len(frames)))
		}
		select {
		case <-c.stop:
			m.logs.Add("info", "stop requested for %s", key)
			m.restore(c, s)
			return
		case <-deadline:
			m.logs.Add("info", "duration reached for %s", key)
			m.restore(c, s)
			return
		case <-tick.C:
		}
	}
}

func (m *Manager) restore(c *cut, s *sender) {
	if err := m.eng.restoreVia(s, c.dev, 150*time.Millisecond); err != nil {
		m.logs.Add("error", "restore %s: %v", c.dev.IP, err)
		return
	}
	m.logs.Add("info", "ARP restored for %s", c.dev.IP)
}

// Stop ends one cut and waits until its restore frames went out.
func (m *Manager) Stop(ip string) error {
	m.mu.Lock()
	c, ok := m.cuts[ip]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("no active cut for %s", ip)
	}
	c.stopOne.Do(func() { close(c.stop) })
	<-c.done
	return nil
}

// StopAll ends every cut. Safe to call from a signal handler.
func (m *Manager) StopAll() {
	m.mu.Lock()
	list := make([]*cut, 0, len(m.cuts))
	for _, c := range m.cuts {
		list = append(list, c)
	}
	m.mu.Unlock()

	if len(list) == 0 {
		return
	}
	m.logs.Add("info", "restoring %d cut(s)", len(list))
	for _, c := range list {
		c.stopOne.Do(func() { close(c.stop) })
	}
	for _, c := range list {
		<-c.done
	}
	m.wg.Wait()
}

// List returns a stable, IP-sorted snapshot of active cuts.
func (m *Manager) List() []CutInfo {
	m.mu.Lock()
	out := make([]CutInfo, 0, len(m.cuts))
	for _, c := range m.cuts {
		out = append(out, c.info())
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		return ipToU32(net.ParseIP(out[i].IP)) < ipToU32(net.ParseIP(out[j].IP))
	})
	return out
}

// EnforceBlocks starts a cut for every scanned device whose MAC is on the
// watch list and is not already cut at its current address. It is safe to call
// on every scan: entries that are already cut are left alone.
func (m *Manager) EnforceBlocks(devs []Device) []CutInfo {
	bl := m.blocks
	if bl == nil || bl.Len() == 0 {
		return nil
	}

	var out []CutInfo
	for _, d := range devs {
		if d.IP == nil || len(d.MAC) != 6 {
			continue
		}
		mac := d.MAC.String()
		if bytes.Equal(d.MAC, m.eng.SelfMAC) {
			continue
		}
		if m.eng.GatewayMAC != nil && bytes.Equal(d.MAC, m.eng.GatewayMAC) {
			continue
		}
		b, ok := bl.Has(mac)
		if !ok {
			continue
		}

		bl.Touch(mac, d.IP.String())
		// A blocked device that moved to a new address must stop poisoning
		// the old one, otherwise a recycled lease would be cut instead.
		if stale := m.cutAtOtherIP(mac, d.IP.String()); stale != "" {
			if err := m.Stop(stale); err == nil {
				m.logs.Add("info", "watchdog released stale cut %s for %s", stale, mac)
			}
		}
		info, err := m.Start(d, b.Mode, 0)
		if err != nil {
			continue
		}
		m.logs.Add("info", "watchdog cut %s (%s)", d.IP, mac)
		out = append(out, info)
	}
	return out
}

// cutAtOtherIP returns the IP of an active cut for mac that is not ip.
func (m *Manager) cutAtOtherIP(mac, ip string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, c := range m.cuts {
		if key != ip && c.dev.MAC.String() == mac {
			return key
		}
	}
	return ""
}

// WatchOnce runs one quiet sweep and re-cuts any blocked device it finds.
// It returns the cuts it started. An empty watch list short-circuits so the
// watchdog costs nothing when unused.
func (m *Manager) WatchOnce(timeout time.Duration) []CutInfo {
	if m.blocks == nil || m.blocks.Len() == 0 {
		return nil
	}
	devs, err := m.eng.Scan(timeout)
	if err != nil {
		m.logs.Add("error", "watchdog scan: %v", err)
		return nil
	}
	return m.EnforceBlocks(devs)
}

// StopMAC ends every active cut for one MAC and waits for the restores.
func (m *Manager) StopMAC(mac string) ([]string, error) {
	n, err := NormalizeMAC(mac)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	targets := make([]*cut, 0, 1)
	ips := make([]string, 0, 1)
	for _, c := range m.cuts {
		if c.dev.MAC.String() == n {
			targets = append(targets, c)
			ips = append(ips, c.dev.IP.String())
		}
	}
	m.mu.Unlock()

	for _, c := range targets {
		c.stopOne.Do(func() { close(c.stop) })
	}
	for _, c := range targets {
		<-c.done
	}
	sort.Strings(ips)
	return ips, nil
}

// LogEntry is one line of the shared console.
type LogEntry struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"`
	Msg   string    `json:"msg"`
}

// LogBuffer is a bounded ring buffer with fan-out to SSE subscribers.
type LogBuffer struct {
	mu      sync.Mutex
	entries []LogEntry
	subs    map[chan LogEntry]struct{}
	max     int
}

func NewLogBuffer(max int) *LogBuffer {
	if max <= 0 {
		max = 500
	}
	return &LogBuffer{max: max, subs: make(map[chan LogEntry]struct{})}
}

func (b *LogBuffer) Add(level, format string, args ...any) {
	e := LogEntry{Time: time.Now(), Level: level, Msg: fmt.Sprintf(format, args...)}
	b.mu.Lock()
	b.entries = append(b.entries, e)
	if len(b.entries) > b.max {
		b.entries = b.entries[len(b.entries)-b.max:]
	}
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
		}
	}
	b.mu.Unlock()
}

func (b *LogBuffer) Snapshot() []LogEntry {
	b.mu.Lock()
	out := make([]LogEntry, len(b.entries))
	copy(out, b.entries)
	b.mu.Unlock()
	return out
}

// Subscribe returns a channel of new entries plus a cancel func.
func (b *LogBuffer) Subscribe() (<-chan LogEntry, func()) {
	ch := make(chan LogEntry, 64)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, ch)
			close(ch)
			b.mu.Unlock()
		})
	}
	return ch, cancel
}
