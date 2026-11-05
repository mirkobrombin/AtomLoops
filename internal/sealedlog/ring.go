package sealedlog

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Device is the storage under a ring: a preallocated file at runtime, the raw
// extent behind it when the loader writes by LBA.
type Device interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
}

// Ring is a fixed number of blocks used round robin: block seq lives at index
// (seq-1) mod Blocks. Only the newest blocks survive; the hot boots.
type Ring struct {
	dev    Device
	Blocks int
	ID     [16]byte
	// Archive, when set, receives every valid block just before it is
	// overwritten, so a cold boot is never lost to the ring wrapping.
	Archive func(Header, []byte) error
}

// Entry is one block found in the ring.
type Entry struct {
	Index  int
	Header Header
	Hash   [32]byte
	Raw    []byte
}

// NewRing wraps dev holding blocks blocks of ring id.
func NewRing(dev Device, blocks int, id [16]byte) *Ring {
	return &Ring{dev: dev, Blocks: blocks, ID: id}
}

// OpenRingFile opens a ring file created by CreateRingFile.
func OpenRingFile(path string) (*Ring, *os.File, error) {
	return openRingFile(path, os.O_RDWR)
}

// ReadRingFile opens the ring at path for reading only, as a reader that is
// not the collector does.
func ReadRingFile(path string) (*Ring, *os.File, error) {
	return openRingFile(path, os.O_RDONLY)
}

func openRingFile(path string, flag int) (*Ring, *os.File, error) {
	f, err := os.OpenFile(path, flag, 0)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	n := int(st.Size() / BlockSize)
	if n < 2 {
		f.Close()
		return nil, nil, fmt.Errorf("sealedlog: %s holds %d blocks, need at least 2", path, n)
	}
	b := make([]byte, BlockSize)
	if _, err := f.ReadAt(b, 0); err != nil {
		f.Close()
		return nil, nil, err
	}
	id, ok := RingOf(b)
	if !ok {
		f.Close()
		return nil, nil, fmt.Errorf("sealedlog: %s is not a ring", path)
	}
	return NewRing(f, n, id), f, nil
}

// CreateRingFile makes a zeroed ring of blocks blocks at path. The file is
// written in full so every block has its place on disk before the loader
// learns the extent.
func CreateRingFile(path string, blocks int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if beforeFill != nil {
		if err := beforeFill(f, int64(blocks)*BlockSize); err != nil {
			f.Close()
			os.Remove(path)
			return err
		}
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		f.Close()
		return err
	}
	for i := 0; i < blocks; i++ {
		if _, err := f.Write(EmptyBlock(id, uint32(i))); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// beforeFill runs on the empty ring file, where a filesystem needs it to keep
// the blocks in place.
var beforeFill func(f *os.File, size int64) error

// Scan returns the valid blocks of the ring ordered by sequence.
func (r *Ring) Scan() ([]Entry, error) {
	var out []Entry
	for i := 0; i < r.Blocks; i++ {
		b := make([]byte, BlockSize)
		if _, err := r.dev.ReadAt(b, int64(i)*BlockSize); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		h, err := ParseHeader(b)
		if err != nil || h.Ring != r.ID || int((h.Seq-1)%uint64(r.Blocks)) != i {
			continue
		}
		out = append(out, Entry{Index: i, Header: h, Hash: Hash(b), Raw: b})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Header.Seq < out[j].Header.Seq })
	return out, nil
}

// Head is the newest block, ok false on an empty ring.
func Head(entries []Entry) (Entry, bool) {
	if len(entries) == 0 {
		return Entry{}, false
	}
	return entries[len(entries)-1], true
}

// NextBoot is the boot number a new boot should use.
func NextBoot(entries []Entry) uint32 {
	var max uint32
	for _, e := range entries {
		if e.Header.Boot > max {
			max = e.Header.Boot
		}
	}
	return max + 1
}

// Append seals payload into the next block for boot.
func (r *Ring) Append(reader *ecdh.PublicKey, boot uint32, counter uint64, payload []byte) (Header, error) {
	entries, err := r.Scan()
	if err != nil {
		return Header{}, err
	}
	h := Header{Ring: r.ID, Seq: 1, Boot: boot, Counter: counter}
	if head, ok := Head(entries); ok {
		h.Seq = head.Header.Seq + 1
		h.Prev = head.Hash
	}
	b, err := Seal(reader, h, payload, nil)
	if err != nil {
		return h, err
	}
	idx := int((h.Seq - 1) % uint64(r.Blocks))
	if r.Archive != nil {
		for _, e := range entries {
			if e.Index == idx {
				if err := r.Archive(e.Header, e.Raw); err != nil {
					return h, err
				}
			}
		}
	}
	if _, err := r.dev.WriteAt(b, int64(idx)*BlockSize); err != nil {
		return h, err
	}
	return h, r.dev.Sync()
}

// Break is a place where the chain does not hold.
type Break struct {
	Seq    uint64
	Reason string
}

// Verify checks the hash chain over consecutive sequences and reports any
// sequence that appears twice. A gap is not a break: older blocks are allowed
// to have left the ring.
func Verify(entries []Entry) []Break {
	var out []Break
	for i := 1; i < len(entries); i++ {
		prev, cur := entries[i-1], entries[i]
		switch {
		case cur.Header.Seq == prev.Header.Seq:
			out = append(out, Break{cur.Header.Seq, "sequence repeated"})
		case cur.Header.Seq == prev.Header.Seq+1 && cur.Header.Prev != prev.Hash:
			out = append(out, Break{cur.Header.Seq, "previous hash mismatch"})
		case cur.Header.Boot < prev.Header.Boot:
			out = append(out, Break{cur.Header.Seq, "boot number went back"})
		case cur.Header.Counter != 0 && prev.Header.Counter != 0 && cur.Header.Counter < prev.Header.Counter:
			out = append(out, Break{cur.Header.Seq, "TPM counter went back"})
		case cur.Header.Counter != 0 && prev.Header.Counter != 0 && cur.Header.Counter > prev.Header.Counter+1:
			out = append(out, Break{cur.Header.Seq, "boots erased: TPM counter jumped"})
		}
	}
	return out
}

// Check is Verify plus the gaps a ring cannot explain: until the ring wraps,
// every sequence from 1 to the newest must still be there.
func (r *Ring) Check(entries []Entry) []Break {
	out := Verify(entries)
	head, ok := Head(entries)
	if !ok || head.Header.Seq > uint64(r.Blocks) {
		return out
	}
	seen := map[uint64]bool{}
	for _, e := range entries {
		seen[e.Header.Seq] = true
	}
	for seq := uint64(1); seq < head.Header.Seq; seq++ {
		if !seen[seq] {
			out = append(out, Break{seq, "block missing from the ring"})
		}
	}
	return out
}

// Boots lists the boot numbers present, oldest first.
func Boots(entries []Entry) []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	for _, e := range entries {
		if !seen[e.Header.Boot] {
			seen[e.Header.Boot] = true
			out = append(out, e.Header.Boot)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Cold is the archive of boots that left the hot ring: one file per boot, the
// sealed blocks copied verbatim so the chain and the encryption survive.
type Cold struct {
	Dir string
	// MaxBytes bounds the archive; the oldest boots go first. 0 is unbounded.
	MaxBytes int64
}

func (c Cold) path(boot uint32) string {
	return filepath.Join(c.Dir, fmt.Sprintf("boot-%08d.slog", boot))
}

func (c Cold) has(boot uint32, seq uint64) (bool, error) {
	b, err := os.ReadFile(c.path(boot))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	for off := 0; off+BlockSize <= len(b); off += BlockSize {
		if h, err := ParseHeader(b[off : off+BlockSize]); err == nil && h.Seq == seq {
			return true, nil
		}
	}
	return false, nil
}

// Put stores one block unless the archive already holds it.
func (c Cold) Put(h Header, raw []byte) error {
	if ok, err := c.has(h.Boot, h.Seq); err != nil || ok {
		return err
	}
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(c.path(h.Boot), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Migrate copies every block of the boots older than the newest keep boots
// into the archive, then prunes the archive to MaxBytes.
func (c Cold) Migrate(entries []Entry, keep int) error {
	boots := Boots(entries)
	if len(boots) <= keep {
		return c.Prune()
	}
	cold := map[uint32]bool{}
	for _, b := range boots[:len(boots)-keep] {
		cold[b] = true
	}
	for _, e := range entries {
		if cold[e.Header.Boot] {
			if err := c.Put(e.Header, e.Raw); err != nil {
				return err
			}
		}
	}
	return c.Prune()
}

// Prune deletes the oldest archived boots until the archive fits MaxBytes.
func (c Cold) Prune() error {
	if c.MaxBytes <= 0 {
		return nil
	}
	ents, err := os.ReadDir(c.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var names []string
	var total int64
	sizes := map[string]int64{}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".slog") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		names = append(names, e.Name())
		sizes[e.Name()] = info.Size()
		total += info.Size()
	}
	sort.Strings(names)
	for _, n := range names {
		if total <= c.MaxBytes {
			break
		}
		if err := os.Remove(filepath.Join(c.Dir, n)); err != nil {
			return err
		}
		total -= sizes[n]
	}
	return nil
}

// ReadCold returns the archived blocks of every boot, ordered by sequence.
func (c Cold) ReadCold() ([]Entry, error) {
	ents, err := os.ReadDir(c.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Entry
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".slog") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(c.Dir, e.Name()))
		if err != nil {
			return nil, err
		}
		for off := 0; off+BlockSize <= len(b); off += BlockSize {
			raw := b[off : off+BlockSize]
			if h, err := ParseHeader(raw); err == nil {
				out = append(out, Entry{Index: -1, Header: h, Hash: Hash(raw), Raw: raw})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Header.Seq < out[j].Header.Seq })
	return out, nil
}
