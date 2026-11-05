package sealedlog

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Extent is a run of the ring on its partition, in bytes from the partition
// start.
type Extent struct {
	Offset uint64
	Length uint64
}

// Map tells the loader where the ring is without a filesystem: the GPT
// partition that holds it and the byte runs of the ring file on it.
type Map struct {
	Ring     [16]byte
	PartUUID string
	Blocks   int
	Extents  []Extent
}

// Encode renders the map as the loader reads it from the ESP.
func (m Map) Encode() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "version=1\nring=%x\npartuuid=%s\nblocks=%d\n", m.Ring, m.PartUUID, m.Blocks)
	for _, e := range m.Extents {
		fmt.Fprintf(&b, "extent=%d,%d\n", e.Offset, e.Length)
	}
	return []byte(b.String())
}

// ParseMap reads an encoded map.
func ParseMap(b []byte) (Map, error) {
	var m Map
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "ring":
			id, err := hex.DecodeString(v)
			if err != nil || len(id) != 16 {
				return m, fmt.Errorf("sealedlog: bad ring id %q", v)
			}
			copy(m.Ring[:], id)
		case "partuuid":
			m.PartUUID = v
		case "blocks":
			m.Blocks, _ = strconv.Atoi(v)
		case "extent":
			o, l, _ := strings.Cut(v, ",")
			off, err1 := strconv.ParseUint(o, 10, 64)
			length, err2 := strconv.ParseUint(l, 10, 64)
			if err1 != nil || err2 != nil {
				return m, fmt.Errorf("sealedlog: bad extent %q", v)
			}
			m.Extents = append(m.Extents, Extent{off, length})
		}
	}
	var total uint64
	for _, e := range m.Extents {
		total += e.Length
	}
	if m.Ring == ([16]byte{}) || m.PartUUID == "" || m.Blocks < 2 || total != uint64(m.Blocks)*BlockSize {
		return m, errors.New("sealedlog: incomplete ring map")
	}
	return m, nil
}

const (
	f2fsMagic         = 0xf2f52010
	f2fsIocSetPinFile = 0x4004f50d
	fsIocFiemap       = 0xc020660b
	fiemapFlagSync    = 0x1
	fiemapExtentLast  = 0x1
	fiemapExtentBad   = 0x2 | 0x4 | 0x8 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800
	fiemapHeader      = 32
	fiemapExtentSize  = 56
)
