package sealedlog

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// EFIVarDir is where Linux exposes the variables.
var EFIVarDir = "/sys/firmware/efi/efivars"

const efivarfsMagic = 0xde5e81e4

// MountEFIVars mounts efivarfs on EFIVarDir when the system booted through
// UEFI and nothing mounted it yet.
func MountEFIVars() error {
	if _, err := os.Stat(EFIVarDir); err != nil {
		return err
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(EFIVarDir, &st); err == nil && uint32(st.Type) == efivarfsMagic {
		return nil
	}
	return syscall.Mount("efivarfs", EFIVarDir, "efivarfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "")
}

func efiPath(name string) string {
	return filepath.Join(EFIVarDir, name+"-"+VendorGUID)
}

// ReadEFIVar returns the data of a variable without its attribute word.
func ReadEFIVar(name string) ([]byte, error) {
	b, err := os.ReadFile(efiPath(name))
	if err != nil {
		return nil, err
	}
	if len(b) < 4 {
		return nil, errors.New("sealedlog: short EFI variable")
	}
	return b[4:], nil
}

const (
	fsIocGetFlags = 0x80086601
	fsIocSetFlags = 0x40086602
	fsImmutableFl = 0x00000010
)

// DeleteEFIVar removes a variable. efivarfs marks files immutable, so the
// flag is cleared first.
func DeleteEFIVar(name string) error {
	p := efiPath(name)
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var flags int
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocGetFlags, uintptr(unsafe.Pointer(&flags))); e == 0 {
		flags &^= fsImmutableFl
		syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocSetFlags, uintptr(unsafe.Pointer(&flags)))
	}
	f.Close()
	return os.Remove(p)
}

// WriteEFIVar replaces a non-volatile variable with data.
func WriteEFIVar(name string, data []byte) error {
	if err := DeleteEFIVar(name); err != nil {
		return err
	}
	b := make([]byte, 4, 4+len(data))
	b[0] = 0x07
	b = append(b, data...)
	f, err := os.OpenFile(efiPath(name), os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
