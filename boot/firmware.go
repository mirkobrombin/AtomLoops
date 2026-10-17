package boot

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mirkobrombin/atomloops/internal/otad"
)

// MountFirmware unions the verified firmware bundles under
// NewRoot/boot/firmware over the base firmware of the root. It fails open,
// bundle by bundle: a bundle that is missing, does not verify against the
// release root key, or does not mount is skipped and the rest still mount,
// because a firmware failure must never stop the boot. A driver bundle, one
// that carries .kernel-abi, is only kept when it was built for the running
// kernel, and stays mounted on its own under /var for the system to
// activate instead of joining the firmware union.
func MountFirmware(rootPubPath string) {
	fwroot := NewRoot + "/boot/firmware"
	if !exists(fwroot) {
		Logf("no firmware dir, base firmware only")
		return
	}
	rootPub, err := os.ReadFile(rootPubPath)
	if err != nil {
		Logf("no firmware root key, base firmware only")
		return
	}
	release := kernelRelease()
	var lowers, maps, loops, mounts []string
	cleanup := func() {
		for _, m := range mounts {
			Unmount(m)
		}
		for _, v := range maps {
			CloseVerity(v)
		}
		for _, l := range loops {
			DetachLoop(l)
		}
	}
	dirs, _ := filepath.Glob(fwroot + "/*/")
	for _, dir := range dirs {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			continue
		}
		name := filepath.Base(dir)
		img, hash := dir+"/firmware-active.img", dir+"/firmware-active.hash"
		if !exists(img) {
			continue
		}
		fw, err := otad.VerifiedFirmwareBundle(dir, "active", rootPub, time.Now(), name)
		if err != nil || !ValidRootHash(fw.VerityHash) {
			Logf("firmware bundle %s unverified, skipped", name)
			continue
		}
		dl, err := AttachLoop(img)
		if err != nil {
			Logf("firmware bundle %s attach failed, skipped", name)
			continue
		}
		hl, err := AttachLoop(hash)
		if err != nil {
			Logf("firmware bundle %s hash attach failed, skipped", name)
			DetachLoop(dl)
			continue
		}
		mapper := name + "-fwverity"
		node, err := OpenVerity(mapper, dl, hl, fw.VerityHash)
		if err != nil || !HasEROFS(node) {
			Logf("firmware bundle %s verity failed, skipped", name)
			CloseVerity(mapper)
			DetachLoop(dl)
			DetachLoop(hl)
			continue
		}
		mnt := NewRoot + "/var/.fw-" + name
		if Mount(node, mnt, "erofs", syscall.MS_RDONLY, "") != nil {
			Logf("firmware bundle %s mount failed, skipped", name)
			CloseVerity(mapper)
			DetachLoop(dl)
			DetachLoop(hl)
			continue
		}
		abi, driver := readABI(mnt + "/.kernel-abi")
		if driver && abi != release {
			Logf("driver bundle %s built for kernel %s != running %s, skipped", name, abi, release)
			Unmount(mnt)
			CloseVerity(mapper)
			DetachLoop(dl)
			DetachLoop(hl)
			continue
		}
		loops = append(loops, dl, hl)
		maps = append(maps, mapper)
		mounts = append(mounts, mnt)
		if driver {
			Logf("driver bundle %s verified + mounted (kernel %s, activated post-boot)", name, abi)
		} else {
			lowers = append([]string{mnt}, lowers...)
			Logf("firmware bundle %s verified + mounted (anchor-verified)", name)
		}
	}
	if len(lowers) == 0 {
		Logf("no firmware bundle mounted, base firmware only")
		return
	}
	base := NewRoot + "/var/.base-firmware"
	if Bind(NewRoot+"/usr/lib/firmware", base) != nil {
		Logf("firmware base bind failed, base only")
		cleanup()
		return
	}
	opts := "lowerdir=" + strings.Join(lowers, ":") + ":" + base
	if syscall.Mount("overlay", NewRoot+"/usr/lib/firmware", "overlay", syscall.MS_RDONLY, opts) == nil {
		Logf("firmware add-on bundles unioned over base firmware")
		return
	}
	Logf("firmware overlay failed, using base firmware")
	Unmount(base)
	cleanup()
}

func readABI(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' {
			return -1
		}
		return r
	}, string(data)), true
}

func kernelRelease() string {
	var u syscall.Utsname
	if syscall.Uname(&u) != nil {
		return ""
	}
	b := make([]byte, 0, len(u.Release))
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
