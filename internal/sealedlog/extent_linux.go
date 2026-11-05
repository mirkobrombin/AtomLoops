package sealedlog

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

func init() { beforeFill = pinAndAllocate }

// pinAndAllocate pins an empty file and reserves its blocks: f2fs refuses
// writes into holes of a pinned file.
func pinAndAllocate(f *os.File, size int64) error {
	if err := Pin(f); err != nil {
		return err
	}
	if err := syscall.Fallocate(int(f.Fd()), 0, 0, size); err != nil && err != syscall.EOPNOTSUPP {
		return err
	}
	return nil
}

// Pin asks f2fs to never move the blocks of f, so the extents the loader
// writes to stay those of the file. Filesystems without the call return an
// error that the caller may ignore when they never relocate data.
func Pin(f *os.File) error {
	var st syscall.Statfs_t
	if err := syscall.Fstatfs(int(f.Fd()), &st); err != nil {
		return err
	}
	if uint32(st.Type) != f2fsMagic {
		return nil
	}
	on := uint32(1)
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), f2fsIocSetPinFile, uintptr(unsafe.Pointer(&on)))
	if e != 0 {
		return e
	}
	return nil
}

// Extents returns the physical runs of f through FIEMAP. Encrypted, inline,
// delayed or unaligned runs are refused: the loader could not write them raw.
func Extents(f *os.File, size uint64) ([]Extent, error) {
	const max = 64
	buf := make([]byte, fiemapHeader+max*fiemapExtentSize)
	binary.LittleEndian.PutUint64(buf[0:], 0)
	binary.LittleEndian.PutUint64(buf[8:], size)
	binary.LittleEndian.PutUint32(buf[16:], fiemapFlagSync)
	binary.LittleEndian.PutUint32(buf[24:], max)
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocFiemap, uintptr(unsafe.Pointer(&buf[0]))); e != 0 {
		return nil, e
	}
	n := int(binary.LittleEndian.Uint32(buf[20:]))
	var out []Extent
	var covered uint64
	for i := 0; i < n; i++ {
		e := buf[fiemapHeader+i*fiemapExtentSize:]
		logical := binary.LittleEndian.Uint64(e[0:])
		physical := binary.LittleEndian.Uint64(e[8:])
		length := binary.LittleEndian.Uint64(e[16:])
		flags := binary.LittleEndian.Uint32(e[40:])
		if flags&fiemapExtentBad != 0 {
			return nil, fmt.Errorf("sealedlog: extent at %d has flags %#x, not raw writable", logical, flags)
		}
		if logical != covered {
			return nil, fmt.Errorf("sealedlog: hole at %d", covered)
		}
		if logical+length > size {
			length = size - logical
		}
		out = append(out, Extent{physical, length})
		covered += length
		if flags&fiemapExtentLast != 0 || covered >= size {
			break
		}
	}
	if covered < size {
		return nil, fmt.Errorf("sealedlog: only %d of %d bytes mapped", covered, size)
	}
	return out, nil
}

// PartUUID finds the GPT partition UUID of the block device holding f.
func PartUUID(f *os.File) (string, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return "", err
	}
	major := (st.Dev >> 8) & 0xfff
	minor := (st.Dev & 0xff) | ((st.Dev >> 12) & 0xfff00)
	dev, err := filepath.EvalSymlinks(fmt.Sprintf("/sys/dev/block/%d:%d", major, minor))
	if err != nil {
		return "", err
	}
	name := filepath.Base(dev)
	if u, err := os.ReadFile(filepath.Join(dev, "uevent")); err == nil {
		for _, l := range strings.Split(string(u), "\n") {
			if v, ok := strings.CutPrefix(l, "PARTUUID="); ok && v != "" {
				return strings.ToLower(v), nil
			}
		}
	}
	links, _ := os.ReadDir("/dev/disk/by-partuuid")
	for _, l := range links {
		t, err := filepath.EvalSymlinks(filepath.Join("/dev/disk/by-partuuid", l.Name()))
		if err == nil && filepath.Base(t) == name {
			return strings.ToLower(l.Name()), nil
		}
	}
	return "", fmt.Errorf("sealedlog: no partition UUID for %s", name)
}

// MapFile pins the ring file and describes where it lives on disk.
func MapFile(path string) (Map, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return Map{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Map{}, err
	}
	_ = Pin(f)
	ext, err := Extents(f, uint64(st.Size()))
	if err != nil {
		return Map{}, err
	}
	uuid, err := PartUUID(f)
	if err != nil {
		return Map{}, err
	}
	b := make([]byte, BlockSize)
	if _, err := f.ReadAt(b, 0); err != nil {
		return Map{}, err
	}
	id, ok := RingOf(b)
	if !ok {
		return Map{}, fmt.Errorf("sealedlog: %s is not a ring", path)
	}
	return Map{Ring: id, PartUUID: uuid, Blocks: int(st.Size() / BlockSize), Extents: ext}, nil
}
