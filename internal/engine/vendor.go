package engine

import (
	"bufio"
	"bytes"
	_ "embed"
	"log"
	"os"
	"strconv"
	"strings"
)

// embeddedOUI is the IEEE MA-L registry, keyed by the 24-bit assignment block
// with the organization name in the second column. It ships inside the binary
// so vendor names work offline with no external file.
//
//go:embed oui.tsv
var embeddedOUI string

// OUITable maps a 24-bit MAC prefix to an organization name.
type OUITable struct {
	m map[string]string
}

// LoadOUI builds the lookup table from the embedded registry and merges an
// optional external IEEE oui.csv or Wireshark manuf file on top. A missing or
// unreadable external file is reported but never fatal: the embedded table is
// enough to run.
func LoadOUI(extraPath string) *OUITable {
	t := &OUITable{m: make(map[string]string, 41000)}
	t.parseRegistry(embeddedOUI)

	if extraPath != "" {
		data, err := os.ReadFile(extraPath)
		if err != nil {
			log.Printf("oui: %v (using embedded registry only)", err)
			return t
		}
		if n := t.parseExternal(data); n == 0 {
			log.Printf("oui: no prefixes recognised in %s (using embedded registry only)", extraPath)
		}
	}
	return t
}

// Lookup returns the organization for a MAC address, an empty string when the
// prefix is not registered, or "Private (randomized)" when the address carries
// the locally-administered bit and is therefore not a vendor assignment.
func (t *OUITable) Lookup(mac string) string {
	key := ouiKey(mac)
	if key == "" {
		return ""
	}
	if t != nil && t.m != nil {
		if name := t.m[key]; name != "" {
			return name
		}
	}
	if octet, err := strconv.ParseUint(key[:2], 16, 8); err == nil && octet&0x02 != 0 {
		return "Private (randomized)"
	}
	return ""
}

// parseRegistry reads the embedded tab-separated table.
func (t *OUITable) parseRegistry(data string) {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		key, name, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		t.put(key, name)
	}
}

// parseExternal accepts both IEEE oui.csv (Registry,Assignment,Organization
// Name,Organization Address) and Wireshark manuf (PREFIX<TAB>short<TAB>long).
// It returns how many prefixes it merged.
func (t *OUITable) parseExternal(data []byte) int {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

	merged := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Registry,") {
			continue
		}
		// IEEE CSV: the assignment lives in the second field.
		if f := strings.Split(line, ","); len(f) >= 3 {
			if key := ouiKey(f[1]); key != "" {
				if t.put(key, f[2]) {
					merged++
				}
				continue
			}
		}
		// Wireshark manuf: prefix, short name, long name (the last wins).
		if f := strings.Split(line, "\t"); len(f) >= 2 {
			if t.put(f[0], f[len(f)-1]) {
				merged++
			}
		}
	}
	if err := sc.Err(); err != nil {
		log.Printf("oui: read external registry: %v", err)
	}
	return merged
}

func (t *OUITable) put(rawKey, rawName string) bool {
	key := ouiKey(rawKey)
	name := strings.Trim(strings.TrimSpace(rawName), `"`)
	if key == "" || name == "" {
		return false
	}
	t.m[key] = name
	return true
}

// ouiKey reduces any MAC spelling ("c4:75:ab:52:61:47", "c4-75-ab", "C475AB")
// to the first six uppercase hex digits. Anything shorter is not an OUI.
func ouiKey(mac string) string {
	var b strings.Builder
	b.Grow(6)
	for i := 0; i < len(mac); i++ {
		c := mac[i]
		switch {
		case c >= '0' && c <= '9':
			b.WriteByte(c)
		case c >= 'a' && c <= 'f':
			b.WriteByte(c - 'a' + 'A')
		case c >= 'A' && c <= 'F':
			b.WriteByte(c)
		}
		if b.Len() == 6 {
			return b.String()
		}
	}
	return ""
}
