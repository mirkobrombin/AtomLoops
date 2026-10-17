package boot

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// NewRoot is where the real root is assembled before switching to it.
const NewRoot = "/sysroot"

// MountRoot mounts the selected root on NewRoot and lays out the writable
// parts around it. An installed system, whose data partition carries
// .atom-var, gets that partition back writable as /var, with /etc as an
// overlay whose upper layer lives in /var, /home and /boot bound from /var,
// and a tmpfs /tmp. Anything else is a live boot: the read-only root under
// a tmpfs overlay, with any data partition and optical medium kept read-only
// under /var so their loop devices keep their backing files. It reports
// whether the system is installed.
func MountRoot(cfg Config, m *Media, root *Root, dataHeld bool) (bool, error) {
	cfg.defaults()
	if dataHeld && exists(cfg.DataMount+"/.atom-var") {
		if err := Mount(root.Source, NewRoot, "erofs", syscall.MS_RDONLY, ""); err != nil {
			return true, err
		}
		if err := Move(cfg.DataMount, NewRoot+"/var"); err != nil {
			return true, errors.New("cannot carry the data partition to /var")
		}
		if err := syscall.Mount("", NewRoot+"/var", "", syscall.MS_REMOUNT, ""); err != nil {
			return true, errors.New("cannot make /var writable")
		}
		Logf("installed: /var on %s (%s)", m.DataDev, MountedFS(NewRoot+"/var"))
		for _, d := range []string{"etc-upper", "etc-work", "home", "boot"} {
			os.MkdirAll(NewRoot+"/var/"+d, 0755)
		}
		if err := Bind(NewRoot+"/var/boot", NewRoot+"/boot"); err != nil {
			Logf("warning: /boot not bound")
		}
		syscall.Mount("overlay", NewRoot+"/etc", "overlay", 0,
			"lowerdir="+NewRoot+"/etc,upperdir="+NewRoot+"/var/etc-upper,workdir="+NewRoot+"/var/etc-work")
		syscall.Mount("tmpfs", NewRoot+"/tmp", "tmpfs", 0, "mode=1777")
		Bind(NewRoot+"/var/home", NewRoot+"/home")
		return true, nil
	}
	if err := Mount(root.Source, "/lower", "erofs", syscall.MS_RDONLY, ""); err != nil {
		return false, err
	}
	if err := Mount("tmpfs", "/over", "tmpfs", 0, "mode=0755"); err != nil {
		return false, err
	}
	os.MkdirAll("/over/upper", 0755)
	os.MkdirAll("/over/work", 0755)
	if err := Mount("overlay", NewRoot, "overlay", 0, "lowerdir=/lower,upperdir=/over/upper,workdir=/over/work"); err != nil {
		return false, err
	}
	if dataHeld {
		if Move(cfg.DataMount, NewRoot+"/var/.data") == nil && Bind(NewRoot+"/var/.data/boot", NewRoot+"/boot") == nil {
			Logf("live: data partition %s kept read-only", m.DataDev)
		}
	}
	if root.Optical {
		if err := Move(cfg.ISOMount, NewRoot+"/var/.iso"); err != nil {
			return false, errors.New("cannot carry the optical boot media")
		}
	}
	return false, nil
}

// MountESP mounts the EFI system partition of the disk the root came from on
// NewRoot/boot/efi. Only that disk is searched, so a portable boot never
// picks up the ESP of an installed disk. An optical root gets the ESP image
// of the medium instead, read-only.
func MountESP(m *Media, root *Root) {
	efi := NewRoot + "/boot/efi"
	if !root.Optical {
		disk := DiskOf(root.Data)
		if strings.HasPrefix(filepath.Base(root.Data), "loop") {
			disk = DiskOf(m.DataDev)
		}
		for _, p := range Partitions() {
			if p.Disk != disk {
				continue
			}
			if Mount(p.Dev, efi, "vfat", 0, "") != nil {
				continue
			}
			if exists(efi + "/EFI/atom") {
				Logf("ESP: %s", p.Dev)
				return
			}
			Unmount(efi)
		}
		return
	}
	img := NewRoot + "/var/.iso/EFI/efiboot.img"
	if exists(efi+"/EFI/atom") || !exists(img) {
		return
	}
	loop, err := AttachLoop(img)
	if err != nil {
		return
	}
	if Mount(loop, efi, "vfat", syscall.MS_RDONLY, "") == nil {
		Logf("ESP: optical image %s", loop)
	}
}

// FindInit returns the init to run inside NewRoot: the init= of the command
// line when it exists there, otherwise the first of candidates that does.
func FindInit(cmdInit string, candidates ...string) string {
	if cmdInit != "" && Executable(NewRoot+cmdInit) {
		return cmdInit
	}
	for _, c := range candidates {
		if Executable(NewRoot + c) {
			return c
		}
	}
	return ""
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Executable reports whether path is a regular file with an execute bit.
func Executable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
}
