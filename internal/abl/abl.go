// Package abl keeps the A/B slot state a bootloader reads from the disk: the
// GPT attributes of the boot partitions on Qualcomm, the devinfo partition on
// Google Tensor.
package abl

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"
)

const (
	attrActive     = 1 << 50
	attrRetryShift = 51
	attrRetryMask  = 7 << attrRetryShift
	attrSuccessful = 1 << 54
	attrUnbootable = 1 << 55
)

type gpt struct {
	sector     int64
	header     []byte
	entriesLBA int64
	count      int
	entrySize  int
	entries    []byte
}

func readGPT(dev io.ReaderAt, sector, lba int64) (*gpt, error) {
	h := make([]byte, sector)
	if _, err := dev.ReadAt(h, lba*sector); err != nil {
		return nil, err
	}
	if string(h[:8]) != "EFI PART" {
		return nil, errors.New("no GPT header")
	}
	le := binary.LittleEndian
	size := le.Uint32(h[12:])
	if size < 92 || int64(size) > sector {
		return nil, fmt.Errorf("GPT header size %d", size)
	}
	check := bytes.Clone(h[:size])
	le.PutUint32(check[16:], 0)
	if crc32.ChecksumIEEE(check) != le.Uint32(h[16:]) {
		return nil, errors.New("GPT header checksum mismatch")
	}
	g := &gpt{sector: sector, header: h, entriesLBA: int64(le.Uint64(h[72:])),
		count: int(le.Uint32(h[80:])), entrySize: int(le.Uint32(h[84:]))}
	if g.count <= 0 || g.count > 1024 || g.entrySize < 128 || g.entrySize > 1024 {
		return nil, errors.New("GPT entry table out of range")
	}
	g.entries = make([]byte, g.count*g.entrySize)
	if _, err := dev.ReadAt(g.entries, g.entriesLBA*sector); err != nil {
		return nil, err
	}
	if crc32.ChecksumIEEE(g.entries) != le.Uint32(h[88:]) {
		return nil, errors.New("GPT entry table checksum mismatch")
	}
	return g, nil
}

func (g *gpt) find(name string) int {
	for i := 0; i < g.count; i++ {
		e := g.entries[i*g.entrySize : (i+1)*g.entrySize]
		u := make([]uint16, 36)
		for j := range u {
			u[j] = binary.LittleEndian.Uint16(e[56+2*j:])
		}
		n := string(utf16.Decode(u))
		if k := strings.IndexByte(n, 0); k >= 0 {
			n = n[:k]
		}
		if n == name {
			return i
		}
	}
	return -1
}

func (g *gpt) attrs(i int) uint64 {
	return binary.LittleEndian.Uint64(g.entries[i*g.entrySize+48:])
}

func (g *gpt) setAttrs(i int, v uint64) {
	binary.LittleEndian.PutUint64(g.entries[i*g.entrySize+48:], v)
}

func (g *gpt) write(dev io.WriterAt) error {
	le := binary.LittleEndian
	le.PutUint32(g.header[88:], crc32.ChecksumIEEE(g.entries))
	size := le.Uint32(g.header[12:])
	le.PutUint32(g.header[16:], 0)
	le.PutUint32(g.header[16:], crc32.ChecksumIEEE(g.header[:size]))
	if _, err := dev.WriteAt(g.entries, g.entriesLBA*g.sector); err != nil {
		return err
	}
	_, err := dev.WriteAt(g.header, int64(le.Uint64(g.header[24:]))*g.sector)
	return err
}

// MarkSuccessful marks the active boot slot on a disk as successful, clears
// its unbootable flag and restores its retry count, in the primary and the
// backup GPT. It reports whether anything changed.
func MarkSuccessful(dev interface {
	io.ReaderAt
	io.WriterAt
}, sector int64) (bool, error) {
	primary, err := readGPT(dev, sector, 1)
	if err != nil {
		return false, err
	}
	backup, err := readGPT(dev, sector, int64(binary.LittleEndian.Uint64(primary.header[32:])))
	if err != nil {
		return false, fmt.Errorf("backup GPT: %w", err)
	}
	slot := -1
	for _, name := range []string{"boot_a", "boot_b"} {
		i := primary.find(name)
		if i < 0 {
			return false, nil
		}
		if primary.attrs(i)&attrActive != 0 {
			if slot >= 0 {
				return false, errors.New("both boot slots are active")
			}
			slot = i
		}
	}
	if slot < 0 {
		return false, errors.New("no boot slot is active")
	}
	old := primary.attrs(slot)
	want := (old | attrSuccessful | attrRetryMask) &^ attrUnbootable
	if old == want {
		return false, nil
	}
	name := "boot_a"
	if primary.find("boot_b") == slot {
		name = "boot_b"
	}
	j := backup.find(name)
	if j < 0 {
		return false, fmt.Errorf("backup GPT has no %s", name)
	}
	primary.setAttrs(slot, want)
	backup.setAttrs(j, want)
	if err := backup.write(dev); err != nil {
		return false, err
	}
	return true, primary.write(dev)
}

// MarkBootedSlot finds the disk carrying the A/B boot partitions and marks
// its active slot successful. A machine without them is left alone.
func MarkBootedSlot(sysBlock, devDir string) (string, error) {
	compat, _ := os.ReadFile("/proc/device-tree/compatible")
	// DEVICE-FIX(gs201): the Pixel bootloader keeps its A/B retry state in the devinfo partition and abandons a slot no booted system marks successful
	if bytes.Contains(compat, []byte("google,gs201")) {
		return markDevinfoSlot(sysBlock, devDir, "/proc/bootconfig")
	}
	// DEVICE-FIX(msm): Qualcomm's bootloader counts down a retry budget in the boot partitions' GPT attributes and refuses the slot once it runs out unless the booted system marks it successful
	if !bytes.Contains(compat, []byte("qcom,")) {
		return "", nil
	}
	disks, err := os.ReadDir(sysBlock)
	if err != nil {
		return "", err
	}
	for _, d := range disks {
		name := d.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "zram") {
			continue
		}
		if !hasPartition(filepath.Join(sysBlock, name), "boot_a") {
			continue
		}
		sector := int64(512)
		if b, err := os.ReadFile(filepath.Join(sysBlock, name, "queue/logical_block_size")); err == nil {
			if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n > 0 {
				sector = n
			}
		}
		f, err := os.OpenFile(filepath.Join(devDir, name), os.O_RDWR, 0)
		if err != nil {
			return "", err
		}
		changed, err := MarkSuccessful(f, sector)
		if err == nil {
			err = f.Sync()
		}
		f.Close()
		if err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		if changed {
			return "marked the active boot slot on " + name + " successful", nil
		}
		return "", nil
	}
	return "", nil
}

func hasPartition(disk, partName string) bool {
	entries, err := os.ReadDir(disk)
	if err != nil {
		return false
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(disk, e.Name(), "uevent"))
		if err == nil && bytes.Contains(b, []byte("\nPARTNAME="+partName+"\n")) {
			return true
		}
	}
	return false
}
