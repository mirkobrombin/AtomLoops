package boot

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	loopCtlGetFree  = 0x4C82
	loopConfigure   = 0x4C0A
	loopClrFd       = 0x4C01
	loFlagsReadOnly = 1
	loNameSize      = 64
	loKeySize       = 32
)

type loopInfo64 struct {
	device         uint64
	inode          uint64
	rdevice        uint64
	offset         uint64
	sizelimit      uint64
	number         uint32
	encryptType    uint32
	encryptKeySize uint32
	flags          uint32
	fileName       [loNameSize]byte
	cryptName      [loNameSize]byte
	encryptKey     [loKeySize]byte
	init           [2]uint64
}

type loopConfig struct {
	fd        uint32
	blockSize uint32
	info      loopInfo64
	reserved  [8]uint64
}

func ioctl(fd, req, arg uintptr) (uintptr, error) {
	r, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg)
	if errno != 0 {
		return r, errno
	}
	return r, nil
}

// AttachLoop binds a file to a free loop device, read-only, and returns the
// loop device path. The binding outlives the call: it stays until DetachLoop,
// so a filesystem or a verity mapping can be stacked on it.
func AttachLoop(file string) (string, error) {
	ctl, err := os.OpenFile("/dev/loop-control", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("loop-control: %w", err)
	}
	defer ctl.Close()
	backing, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer backing.Close()
	for attempt := 0; attempt < 8; attempt++ {
		n, err := ioctl(ctl.Fd(), loopCtlGetFree, 0)
		if err != nil {
			return "", fmt.Errorf("no free loop device: %w", err)
		}
		dev := fmt.Sprintf("/dev/loop%d", n)
		lf, err := os.OpenFile(dev, os.O_RDONLY, 0)
		if err != nil {
			return "", err
		}
		cfg := loopConfig{fd: uint32(backing.Fd())}
		cfg.info.flags = loFlagsReadOnly
		copy(cfg.info.fileName[:loNameSize-1], file)
		_, err = ioctl(lf.Fd(), loopConfigure, uintptr(unsafe.Pointer(&cfg)))
		lf.Close()
		if err == syscall.EBUSY {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("%s -> %s: %w", file, dev, err)
		}
		return dev, nil
	}
	return "", fmt.Errorf("%s: loop devices kept being taken", file)
}

// DetachLoop releases a loop device bound by AttachLoop.
func DetachLoop(dev string) error {
	f, err := os.OpenFile(dev, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = ioctl(f.Fd(), loopClrFd, 0)
	return err
}
