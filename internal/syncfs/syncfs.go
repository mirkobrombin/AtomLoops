// Package syncfs flushes the whole filesystem a file lives on.
package syncfs

import (
	"os"
	"syscall"
)

// File writes back every dirty page and inode of the filesystem holding f.
func File(f *os.File) error {
	if _, _, errno := syscall.Syscall(sysSyncfs, f.Fd(), 0, 0); errno != 0 {
		return errno
	}
	return nil
}
