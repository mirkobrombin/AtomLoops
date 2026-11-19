package abl

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
)

const (
	sector  = 512
	sectors = 2048
	count   = 128
	esize   = 128
)

func fakeDisk(t *testing.T, attrs map[string]uint64) string {
	t.Helper()
	le := binary.LittleEndian
	entries := make([]byte, count*esize)
	i := 0
	for _, name := range []string{"xbl_a", "boot_a", "boot_b", "userdata"} {
		e := entries[i*esize:]
		e[0] = 1
		le.PutUint64(e[32:], uint64(100+i*10))
		le.PutUint64(e[40:], uint64(109+i*10))
		le.PutUint64(e[48:], attrs[name])
		for j, u := range utf16.Encode([]rune(name)) {
			le.PutUint16(e[56+2*j:], u)
		}
		i++
	}
	disk := make([]byte, sectors*sector)
	tableSectors := int64(count * esize / sector)
	header := func(self, other, table int64) []byte {
		h := make([]byte, sector)
		copy(h, "EFI PART")
		le.PutUint32(h[8:], 0x10000)
		le.PutUint32(h[12:], 92)
		le.PutUint64(h[24:], uint64(self))
		le.PutUint64(h[32:], uint64(other))
		le.PutUint64(h[72:], uint64(table))
		le.PutUint32(h[80:], count)
		le.PutUint32(h[84:], esize)
		le.PutUint32(h[88:], crc32.ChecksumIEEE(entries))
		le.PutUint32(h[16:], crc32.ChecksumIEEE(h[:92]))
		return h
	}
	last := int64(sectors - 1)
	copy(disk[sector:], header(1, last, 2))
	copy(disk[2*sector:], entries)
	copy(disk[(last-tableSectors)*sector:], entries)
	copy(disk[last*sector:], header(last, 1, last-tableSectors))
	path := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(path, disk, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func attrsOf(t *testing.T, path, name string) (primary, backup uint64) {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := readGPT(f, sector, 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := readGPT(f, sector, sectors-1)
	if err != nil {
		t.Fatal(err)
	}
	return p.attrs(p.find(name)), b.attrs(b.find(name))
}

func mark(t *testing.T, path string) (bool, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return MarkSuccessful(f, sector)
}

func TestMarksTheActiveSlotInBothTables(t *testing.T) {
	const ro = 1 << 60
	stuck := uint64(ro | 3<<48 | attrActive | attrUnbootable)
	path := fakeDisk(t, map[string]uint64{"boot_a": stuck, "boot_b": ro | 1<<48})
	changed, err := mark(t, path)
	if err != nil || !changed {
		t.Fatalf("changed %v, %v", changed, err)
	}
	want := uint64(ro | 3<<48 | attrActive | attrSuccessful | attrRetryMask)
	if p, b := attrsOf(t, path, "boot_a"); p != want || b != want {
		t.Fatalf("boot_a %#x / %#x, want %#x", p, b, want)
	}
	if p, _ := attrsOf(t, path, "boot_b"); p != ro|1<<48 {
		t.Fatalf("boot_b touched: %#x", p)
	}
	if changed, err := mark(t, path); err != nil || changed {
		t.Fatalf("second run changed %v, %v", changed, err)
	}
}

func TestNoActiveSlotChangesNothing(t *testing.T) {
	path := fakeDisk(t, map[string]uint64{})
	before, _ := os.ReadFile(path)
	if _, err := mark(t, path); err == nil {
		t.Fatal("no active slot must be reported")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("disk changed")
	}
}

func TestRefusesACorruptTable(t *testing.T) {
	path := fakeDisk(t, map[string]uint64{"boot_a": attrActive})
	b, _ := os.ReadFile(path)
	b[2*sector+48] ^= 1
	os.WriteFile(path, b, 0o644)
	if _, err := mark(t, path); err == nil {
		t.Fatal("a table with a bad checksum must not be rewritten")
	}
}
