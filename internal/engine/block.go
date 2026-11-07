package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Block is one MAC-keyed entry on the watchdog list. A blocked device is
// re-cut whenever it appears on the segment again, even when DHCP hands it a
// new address.
type Block struct {
	MAC    string    `json:"mac"`
	Label  string    `json:"label,omitempty"`
	Mode   Mode      `json:"mode"`
	Added  time.Time `json:"added"`
	IP     string    `json:"ip,omitempty"`
	Vendor string    `json:"vendor,omitempty"`
}

// NormalizeMAC canonicalizes "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff" and
// mixed case into the lower-case colon form used as the list key.
func NormalizeMAC(s string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil {
		return "", fmt.Errorf("invalid mac %q", s)
	}
	if len(hw) != 6 {
		return "", fmt.Errorf("invalid mac %q: need 6 bytes", s)
	}
	return hw.String(), nil
}

type stateFile struct {
	Blocks []Block `json:"blocks"`
}

// BlockList is a MAC-keyed, JSON-backed watch list.
type BlockList struct {
	path string

	mu    sync.Mutex
	items map[string]Block
}

// LoadBlockList reads the state file. A missing file yields an empty list.
func LoadBlockList(path string) (*BlockList, error) {
	bl := &BlockList{path: path, items: make(map[string]Block)}
	if path == "" {
		return bl, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return bl, nil
	}
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return bl, nil
	}
	var sf stateFile
	if err := json.Unmarshal(raw, &sf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, b := range sf.Blocks {
		mac, err := NormalizeMAC(b.MAC)
		if err != nil {
			continue
		}
		b.MAC = mac
		if b.Mode != ModeBoth {
			b.Mode = ModeGateway
		}
		bl.items[mac] = b
	}
	return bl, nil
}

// Path returns the backing file, empty when the list is memory only.
func (bl *BlockList) Path() string { return bl.path }

// Len returns how many MACs are blocked.
func (bl *BlockList) Len() int {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	return len(bl.items)
}

// Has reports whether a MAC is blocked and returns its entry.
func (bl *BlockList) Has(mac string) (Block, bool) {
	n, err := NormalizeMAC(mac)
	if err != nil {
		return Block{}, false
	}
	bl.mu.Lock()
	defer bl.mu.Unlock()
	b, ok := bl.items[n]
	return b, ok
}

// List returns a stable snapshot sorted by MAC.
func (bl *BlockList) List() []Block {
	bl.mu.Lock()
	out := make([]Block, 0, len(bl.items))
	for _, b := range bl.items {
		out = append(out, b)
	}
	bl.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

// Add inserts or replaces one entry and persists the list. Re-adding an
// existing MAC keeps its original "added" timestamp and, when the caller did
// not supply them, its label, last known address, and vendor.
func (bl *BlockList) Add(b Block) (Block, error) {
	mac, err := NormalizeMAC(b.MAC)
	if err != nil {
		return Block{}, err
	}
	if b.Mode != ModeBoth {
		b.Mode = ModeGateway
	}
	b.MAC = mac

	bl.mu.Lock()
	defer bl.mu.Unlock()
	if old, ok := bl.items[mac]; ok {
		if b.Added.IsZero() {
			b.Added = old.Added
		}
		if b.IP == "" {
			b.IP = old.IP
		}
		if b.Vendor == "" {
			b.Vendor = old.Vendor
		}
		if b.Label == "" {
			b.Label = old.Label
		}
	}
	if b.Added.IsZero() {
		b.Added = time.Now()
	}
	bl.items[mac] = b
	if err := bl.saveLocked(); err != nil {
		return b, err
	}
	return b, nil
}

// Remove drops one entry and persists the list.
func (bl *BlockList) Remove(mac string) (Block, error) {
	n, err := NormalizeMAC(mac)
	if err != nil {
		return Block{}, err
	}
	bl.mu.Lock()
	defer bl.mu.Unlock()
	b, ok := bl.items[n]
	if !ok {
		return Block{}, fmt.Errorf("%s is not blocked", n)
	}
	delete(bl.items, n)
	if err := bl.saveLocked(); err != nil {
		return b, err
	}
	return b, nil
}

// Touch records the address a blocked MAC was last seen at. The file is only
// rewritten when the address actually changes, so the watchdog stays quiet.
func (bl *BlockList) Touch(mac, ip string) {
	n, err := NormalizeMAC(mac)
	if err != nil {
		return
	}
	bl.mu.Lock()
	defer bl.mu.Unlock()
	b, ok := bl.items[n]
	if !ok || b.IP == ip {
		return
	}
	b.IP = ip
	bl.items[n] = b
	_ = bl.saveLocked()
}

func (bl *BlockList) saveLocked() error {
	if bl.path == "" {
		return nil
	}
	out := stateFile{Blocks: make([]Block, 0, len(bl.items))}
	for _, b := range bl.items {
		out.Blocks = append(out.Blocks, b)
	}
	sort.Slice(out.Blocks, func(i, j int) bool { return out.Blocks[i].MAC < out.Blocks[j].MAC })

	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	dir := filepath.Dir(bl.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".hushwire-state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, bl.path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
