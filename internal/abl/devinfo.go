package abl

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unsafe"
)

const (
	devinfoMagic      = 0x49564544
	devinfoHeaderSize = 128
	devinfoSlots      = 0x30
	devinfoSlotSize   = 4
	devinfoFlags      = 1
	devinfoSuccessful = 0x02
	devinfoMaxSize    = 1 << 20
	devinfoMajor      = 3
	devinfoMinor      = 15

	blkROSet = 0x125d
	blkROGet = 0x125e
)

var slotSuffix = regexp.MustCompile(`(?m)^androidboot\.slot_suffix = "_([ab])"$`)

func readDevinfo(dev io.ReaderAt) ([]byte, error) {
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.NewSectionReader(dev, 0, devinfoMaxSize+1))
	if err != nil {
		return nil, err
	}
	if n > devinfoMaxSize {
		return nil, errors.New("devinfo is larger than 1 MiB")
	}
	if n < devinfoHeaderSize {
		return nil, fmt.Errorf("devinfo holds %d bytes, its header needs %d", n, devinfoHeaderSize)
	}
	return buf.Bytes(), nil
}

// MarkDevinfoSuccessful sets the successful flag of one slot in the A/B data a
// Google Tensor bootloader keeps in its devinfo partition. Only the slot bytes
// change, and the whole partition is read back to prove it. It reports whether
// anything changed.
func MarkDevinfoSuccessful(dev interface {
	io.ReaderAt
	io.WriterAt
}, slot int) (bool, error) {
	if slot != 0 && slot != 1 {
		return false, fmt.Errorf("no A/B slot %d", slot)
	}
	orig, err := readDevinfo(dev)
	if err != nil {
		return false, err
	}
	le := binary.LittleEndian
	if magic := le.Uint32(orig); magic != devinfoMagic {
		return false, fmt.Errorf("devinfo magic %#x is not DEVI", magic)
	}
	if major, minor := le.Uint16(orig[4:]), le.Uint16(orig[6:]); major != devinfoMajor || minor != devinfoMinor {
		return false, fmt.Errorf("devinfo layout %d.%d is not the verified %d.%d", major, minor, devinfoMajor, devinfoMinor)
	}
	flag := devinfoSlots + slot*devinfoSlotSize + devinfoFlags
	if orig[flag]&devinfoSuccessful != 0 {
		return false, nil
	}
	header := bytes.Clone(orig[:devinfoHeaderSize])
	header[flag] |= devinfoSuccessful
	if _, err := dev.WriteAt(header, 0); err != nil {
		return false, err
	}
	if s, ok := dev.(interface{ Sync() error }); ok {
		if err := s.Sync(); err != nil {
			return false, err
		}
	}
	want := bytes.Clone(orig)
	copy(want, header)
	after, err := readDevinfo(dev)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(after, want) {
		return false, errors.New("devinfo does not read back as written")
	}
	return true, nil
}

func bootedSlot(bootconfig string) (int, error) {
	b, err := os.ReadFile(bootconfig)
	if err != nil {
		return 0, err
	}
	m := slotSuffix.FindSubmatch(b)
	if m == nil {
		return 0, errors.New("the bootloader passed no androidboot.slot_suffix")
	}
	return int(m[1][0] - 'a'), nil
}

func findPartition(sysBlock, partName string) (disk, part string) {
	disks, err := os.ReadDir(sysBlock)
	if err != nil {
		return "", ""
	}
	for _, d := range disks {
		entries, err := os.ReadDir(filepath.Join(sysBlock, d.Name()))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), d.Name()) {
				continue
			}
			b, err := os.ReadFile(filepath.Join(sysBlock, d.Name(), e.Name(), "uevent"))
			if err == nil && bytes.Contains(b, []byte("\nPARTNAME="+partName+"\n")) {
				return d.Name(), e.Name()
			}
		}
	}
	return "", ""
}

func blockReadOnly(f *os.File) (bool, bool) {
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeDevice == 0 || fi.Mode()&os.ModeCharDevice != 0 {
		return false, false
	}
	var ro int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), blkROGet, uintptr(unsafe.Pointer(&ro))); e != 0 {
		return false, false
	}
	return ro != 0, true
}

func setBlockReadOnly(f *os.File, ro bool) error {
	var v int32
	if ro {
		v = 1
	}
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), blkROSet, uintptr(unsafe.Pointer(&v))); e != 0 {
		return e
	}
	return nil
}

func writable(path string) (*os.File, func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_SYNC, 0)
	if err != nil {
		return nil, nil, err
	}
	ro, block := blockReadOnly(f)
	if block && ro {
		if err := setBlockReadOnly(f, false); err != nil {
			f.Close()
			return nil, nil, fmt.Errorf("%s: lift read-only: %w", path, err)
		}
	}
	return f, func() {
		if block && ro {
			_ = setBlockReadOnly(f, true)
		}
		f.Close()
	}, nil
}

func markDevinfoSlot(sysBlock, devDir, bootconfig string) (string, error) {
	slot, err := bootedSlot(bootconfig)
	if err != nil {
		return "", err
	}
	disk, part := findPartition(sysBlock, "devinfo")
	if part == "" {
		return "", errors.New("no devinfo partition")
	}
	_, closeDisk, err := writable(filepath.Join(devDir, disk))
	if err != nil {
		return "", err
	}
	defer closeDisk()
	f, closePart, err := writable(filepath.Join(devDir, part))
	if err != nil {
		return "", err
	}
	defer closePart()
	changed, err := MarkDevinfoSuccessful(f, slot)
	if err != nil {
		return "", fmt.Errorf("%s: %w", part, err)
	}
	if !changed {
		return "", nil
	}
	return fmt.Sprintf("marked boot slot %c successful in %s", 'a'+slot, part), nil
}
