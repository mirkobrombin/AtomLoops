package boot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const blkROSet = 0x125d

// GuardDisks sets every block device read-only except the partition named keep
// and the disk that holds it, so a device whose disks carry firmware and
// calibration partitions exposes only its data partition to the boot. It
// returns how many block devices it saw and fails when keep is missing or any
// other device stays writable.
func GuardDisks(keep string) (int, error) {
	entries, err := os.ReadDir("/sys/class/block")
	if err != nil {
		return 0, err
	}
	keepDev := ""
	for _, e := range entries {
		if ueventValue(e.Name(), "PARTNAME") == keep && exists("/sys/class/block/"+e.Name()+"/partition") {
			keepDev = "/dev/" + e.Name()
			break
		}
	}
	if keepDev == "" {
		return 0, fmt.Errorf("no partition named %s yet", keep)
	}
	keepDisk := filepath.Base(DiskOf(keepDev))
	seen := 0
	for _, e := range entries {
		name := e.Name()
		if !guardedName(name) {
			continue
		}
		seen++
		if "/dev/"+name == keepDev || name == keepDisk {
			continue
		}
		if err := setReadOnly("/dev/" + name); err != nil {
			return seen, fmt.Errorf("%s stays writable: %w", name, err)
		}
	}
	return seen, nil
}

func guardedName(name string) bool {
	for _, p := range []string{"loop", "ram", "dm-", "zram", "nbd"} {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	return true
}

func setReadOnly(dev string) error {
	f, err := os.OpenFile(dev, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	one := int32(1)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), blkROSet, uintptr(unsafe.Pointer(&one))); errno != 0 {
		return errno
	}
	ro, err := os.ReadFile("/sys/class/block/" + filepath.Base(dev) + "/ro")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(ro)) != "1" {
		return fmt.Errorf("ro flag not set")
	}
	return nil
}
