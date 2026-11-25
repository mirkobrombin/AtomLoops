package otad

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ErrNoSpace reports that an update does not fit on the partition it is staged
// to. It is raised before the download starts, so no bandwidth is spent on a
// release the device cannot hold.
var ErrNoSpace = errors.New("not enough free space")

var freeSpace = func(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

func ensureSpace(dest string, need int64) error {
	if need <= 0 {
		return nil
	}
	if info, err := os.Stat(dest + ".tmp"); err == nil {
		need -= info.Size()
		if need <= 0 {
			return nil
		}
	}
	dir := filepath.Dir(dest)
	free, err := freeSpace(dir)
	if err != nil {
		return nil
	}
	if free < need {
		return fmt.Errorf("%w on %s for %s: needs %s, %s free", ErrNoSpace, dir, filepath.Base(dest), humanSize(need), humanSize(free))
	}
	return nil
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
