package otad

import (
	"os"
	"syscall"
)

const (
	f2fsIocWriteCheckpoint = 0xf507
	sysSyncfs              = 306
)

// commitDir makes every rename and write under dir durable before the loader is
// pointed at it. f2fs keeps a renamed entry in its node log until the next
// checkpoint, and a read-only mount at early boot does not replay that log, so
// the slot would be missing on the very next boot. The checkpoint ioctl only
// exists on f2fs; on any other filesystem the directory fsync and syncfs suffice.
func commitDir(dir string) error {
	if err := syncDir(dir); err != nil {
		return err
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, _, errno := syscall.Syscall(sysSyncfs, f.Fd(), 0, 0); errno != 0 {
		return errno
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), f2fsIocWriteCheckpoint, 0); errno != 0 &&
		errno != syscall.ENOTTY && errno != syscall.EINVAL && errno != syscall.EOPNOTSUPP && errno != syscall.EPERM {
		return errno
	}
	return nil
}
