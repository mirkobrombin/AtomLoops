package boot

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// VeritySuperblock is the header veritysetup format writes at the start of a
// hash device. It carries everything the kernel table needs except the root
// hash, which must come from a trusted source.
type VeritySuperblock struct {
	Version       uint32
	HashType      uint32
	Algorithm     string
	DataBlockSize uint32
	HashBlockSize uint32
	DataBlocks    uint64
	Salt          []byte
}

var verityMagic = []byte("verity\x00\x00")

// ReadVeritySuperblock reads and checks the superblock of a hash device.
func ReadVeritySuperblock(hashDev string) (*VeritySuperblock, error) {
	f, err := os.Open(hashDev)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 512)
	if _, err := f.ReadAt(buf, 0); err != nil {
		return nil, err
	}
	return ParseVeritySuperblock(buf)
}

// ParseVeritySuperblock decodes the 512-byte verity superblock.
func ParseVeritySuperblock(buf []byte) (*VeritySuperblock, error) {
	if len(buf) < 512 || !bytes.Equal(buf[:8], verityMagic) {
		return nil, errors.New("not a verity hash device")
	}
	le := binary.LittleEndian
	sb := &VeritySuperblock{
		Version:       le.Uint32(buf[8:]),
		HashType:      le.Uint32(buf[12:]),
		Algorithm:     string(bytes.TrimRight(buf[32:64], "\x00")),
		DataBlockSize: le.Uint32(buf[64:]),
		HashBlockSize: le.Uint32(buf[68:]),
		DataBlocks:    le.Uint64(buf[72:]),
	}
	saltSize := int(le.Uint16(buf[80:]))
	if sb.Version != 1 || sb.HashType != 1 || saltSize > 256 {
		return nil, fmt.Errorf("unsupported verity superblock (version %d, type %d)", sb.Version, sb.HashType)
	}
	if sb.Algorithm != "sha256" {
		return nil, fmt.Errorf("unsupported verity hash %q", sb.Algorithm)
	}
	for _, size := range []uint32{sb.DataBlockSize, sb.HashBlockSize} {
		if size < 512 || size > 65536 || size&(size-1) != 0 {
			return nil, fmt.Errorf("invalid verity block size %d", size)
		}
	}
	if sb.DataBlocks == 0 {
		return nil, errors.New("verity superblock lists no data blocks")
	}
	sb.Salt = append([]byte(nil), buf[88:88+saltSize]...)
	return sb, nil
}

// VerityRootHash computes the root hash of a hash device from its top level
// block, without the kernel. It only selects which hash device to map: the
// mapping itself still checks every block against the signed root hash.
func VerityRootHash(hashDev string) (string, *VeritySuperblock, error) {
	f, err := os.Open(hashDev)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	head := make([]byte, 512)
	if _, err := f.ReadAt(head, 0); err != nil {
		return "", nil, err
	}
	sb, err := ParseVeritySuperblock(head)
	if err != nil {
		return "", nil, err
	}
	top := make([]byte, sb.HashBlockSize)
	if _, err := f.ReadAt(top, int64(sb.HashBlockSize)); err != nil {
		return "", nil, err
	}
	h := sha256.New()
	h.Write(sb.Salt)
	h.Write(top)
	return hex.EncodeToString(h.Sum(nil)), sb, nil
}

// ValidRootHash reports whether h is a sha256 root hash in hex.
func ValidRootHash(h string) bool {
	b, err := hex.DecodeString(h)
	return err == nil && len(b) == 32
}

// VerityTable is the kernel dm-verity table line for a data and hash device
// pair, both given as major:minor.
func VerityTable(sb *VeritySuperblock, dataDev, hashDev, rootHash string) string {
	salt := "-"
	if len(sb.Salt) > 0 {
		salt = hex.EncodeToString(sb.Salt)
	}
	return fmt.Sprintf("%d %s %s %d %d %d 1 %s %s %s",
		sb.HashType, dataDev, hashDev, sb.DataBlockSize, sb.HashBlockSize,
		sb.DataBlocks, sb.Algorithm, strings.ToLower(rootHash), salt)
}

func devNumber(path string) (string, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return "", err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFBLK {
		return "", fmt.Errorf("%s is not a block device", path)
	}
	major := (st.Rdev >> 8) & 0xfff
	minor := (st.Rdev & 0xff) | ((st.Rdev >> 12) & 0xfff00)
	return fmt.Sprintf("%d:%d", major, minor), nil
}

const (
	dmIoctlSize     = 312
	dmTargetSpecLen = 40
	dmReadOnlyFlag  = 1 << 0
	dmDevCreate     = 3
	dmDevRemove     = 4
	dmDevSuspend    = 6
	dmTableLoad     = 9
	dmDeferredFlag  = 1 << 17
)

func dmRequest(nr uintptr) uintptr {
	return 3<<30 | dmIoctlSize<<16 | 0xfd<<8 | nr
}

type dmHeader struct {
	version     [3]uint32
	dataSize    uint32
	dataStart   uint32
	targetCount uint32
	openCount   int32
	flags       uint32
	eventNr     uint32
	padding     uint32
	dev         uint64
	name        [128]byte
	uuid        [129]byte
	data        [7]byte
}

func dmCall(nr uintptr, name string, flags uint32, payload []byte, targets uint32) (*dmHeader, error) {
	if len(name) == 0 || len(name) >= 128 || strings.ContainsAny(name, "/") {
		return nil, fmt.Errorf("invalid mapping name %q", name)
	}
	ctl, err := os.OpenFile("/dev/mapper/control", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("device-mapper control: %w", err)
	}
	defer ctl.Close()
	size := dmIoctlSize + len(payload)
	if size < 16384 {
		size = 16384
	}
	buf := make([]byte, size)
	h := (*dmHeader)(unsafe.Pointer(&buf[0]))
	h.version = [3]uint32{4, 0, 0}
	h.dataSize = uint32(size)
	h.dataStart = dmIoctlSize
	h.targetCount = targets
	h.flags = flags
	copy(h.name[:], name)
	copy(buf[dmIoctlSize:], payload)
	if _, err := ioctl(ctl.Fd(), dmRequest(nr), uintptr(unsafe.Pointer(&buf[0]))); err != nil {
		return nil, err
	}
	out := *h
	return &out, nil
}

func verityTarget(sectors uint64, params string) []byte {
	return dmTarget(0, sectors, "verity", params)
}

func dmTarget(start, sectors uint64, kind, params string) []byte {
	plen := len(params) + 1
	total := dmTargetSpecLen + (plen+7)&^7
	buf := make([]byte, total)
	le := binary.LittleEndian
	le.PutUint64(buf[0:], start)
	le.PutUint64(buf[8:], sectors)
	le.PutUint32(buf[20:], uint32(total))
	copy(buf[24:40], kind)
	copy(buf[dmTargetSpecLen:], params)
	return buf
}

// Segment is one run of sectors of a device, in 512-byte sectors.
type Segment struct {
	Dev     string
	Start   uint64
	Sectors uint64
}

// OpenLinear maps the segments, in order, as one read-only device under
// /dev/mapper/name: how a partition stored in pieces of a larger one, such as
// an Android logical partition in super, is read as a block device.
func OpenLinear(name string, segs []Segment) (string, error) {
	if len(segs) == 0 {
		return "", errors.New("no segment to map")
	}
	var table []byte
	at := uint64(0)
	for _, s := range segs {
		dev, err := devNumber(s.Dev)
		if err != nil {
			return "", err
		}
		table = append(table, dmTarget(at, s.Sectors, "linear", fmt.Sprintf("%s %d", dev, s.Start))...)
		at += s.Sectors
	}
	return openMapping(name, table, uint32(len(segs)))
}

// OpenVerity maps dataDev through dm-verity under /dev/mapper/name, checked
// against rootHash with the parameters in the superblock of hashDev. The
// mapping is read-only. A wrong root hash still creates the mapping; reads
// fail, which is why callers confirm with a read before trusting it.
func OpenVerity(name, dataDev, hashDev, rootHash string) (string, error) {
	if !ValidRootHash(rootHash) {
		return "", errors.New("invalid root hash")
	}
	sb, err := ReadVeritySuperblock(hashDev)
	if err != nil {
		return "", fmt.Errorf("%s: %w", hashDev, err)
	}
	data, err := devNumber(dataDev)
	if err != nil {
		return "", err
	}
	hash, err := devNumber(hashDev)
	if err != nil {
		return "", err
	}
	sectors := sb.DataBlocks * uint64(sb.DataBlockSize) / 512
	return openMapping(name, verityTarget(sectors, VerityTable(sb, data, hash, rootHash)), 1)
}

func openMapping(name string, table []byte, targets uint32) (string, error) {
	created, err := dmCall(dmDevCreate, name, dmReadOnlyFlag, nil, 0)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", name, err)
	}
	if _, err := dmCall(dmTableLoad, name, dmReadOnlyFlag, table, targets); err != nil {
		dmCall(dmDevRemove, name, 0, nil, 0)
		return "", fmt.Errorf("load %s: %w", name, err)
	}
	if _, err := dmCall(dmDevSuspend, name, 0, nil, 0); err != nil {
		dmCall(dmDevRemove, name, 0, nil, 0)
		return "", fmt.Errorf("resume %s: %w", name, err)
	}
	node := filepath.Join("/dev/mapper", name)
	os.MkdirAll("/dev/mapper", 0755)
	os.Remove(node)
	if err := syscall.Mknod(node, syscall.S_IFBLK|0600, int(created.dev)); err != nil {
		CloseMapping(name)
		return "", fmt.Errorf("node %s: %w", node, err)
	}
	return node, nil
}

// CloseVerity removes a mapping made by OpenVerity. Closing a mapping that
// does not exist is not an error.
func CloseVerity(name string) error { return CloseMapping(name) }

// CloseMapping removes a mapping made by OpenVerity or OpenLinear. Closing a
// mapping that does not exist is not an error.
func CloseMapping(name string) error {
	os.Remove(filepath.Join("/dev/mapper", name))
	var err error
	for i := 0; i < 40; i++ {
		if _, err = dmCall(dmDevRemove, name, 0, nil, 0); err == nil || err == syscall.ENXIO {
			return nil
		}
		if err != syscall.EBUSY {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return err
}

// CloseVerityDeferred removes a mapping that may still be in use: the kernel
// drops it on its last close instead of refusing with EBUSY.
func CloseVerityDeferred(name string) error {
	os.Remove(filepath.Join("/dev/mapper", name))
	if _, err := dmCall(dmDevRemove, name, dmDeferredFlag, nil, 0); err != nil && err != syscall.ENXIO {
		return err
	}
	return nil
}

// DevBytes is the size of a block device in bytes, 0 when it cannot be read.
func DevBytes(dev string) uint64 {
	b, err := os.ReadFile(filepath.Join("/sys/class/block", filepath.Base(dev), "size"))
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return n * 512
}

// HasEROFS reports whether the device starts with an EROFS superblock. On a
// verity mapping this read also proves the root hash: a mismatch fails it.
func HasEROFS(dev string) bool {
	f, err := os.Open(dev)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.ReadAt(magic[:], 1024); err != nil {
		return false
	}
	return magic == [4]byte{0xe2, 0xe1, 0xf5, 0xe0}
}
