//go:build linux

package main

import (
	"bytes"
	"path/filepath"
	"syscall"
)

func watchStateFile(path string, notify func()) {
	if path == "" {
		return
	}
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
	if err != nil {
		return
	}
	dir, name := filepath.Dir(path), []byte(filepath.Base(path))
	if _, err := syscall.InotifyAddWatch(fd, dir, syscall.IN_CLOSE_WRITE|syscall.IN_MOVED_TO|syscall.IN_DELETE); err != nil {
		syscall.Close(fd)
		return
	}
	go func() {
		defer syscall.Close(fd)
		buf := make([]byte, 4096)
		for {
			n, err := syscall.Read(fd, buf)
			if err != nil {
				if err == syscall.EINTR {
					continue
				}
				return
			}
			for off := 0; off+syscall.SizeofInotifyEvent <= n; {
				length := int(nativeUint32(buf[off+12 : off+16]))
				start := off + syscall.SizeofInotifyEvent
				end := start + length
				if end > n {
					break
				}
				if bytes.Equal(bytes.TrimRight(buf[start:end], "\x00"), name) {
					notify()
				}
				off = end
			}
		}
	}()
}

func nativeUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
