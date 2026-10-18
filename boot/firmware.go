package boot

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
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
// activate instead of joining the firmware union. A bundle that carries
// .overlay names a directory under /usr and a version: it is mounted over
// that directory instead, and only when its version is above the one in the
// directory's .overlay-version, so a newer root always wins over an older
// bundle.
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
	var firmware []*mountedBundle
	overlays := map[string]*mountedBundle{}
	for _, dir := range bundleDirs(fwroot) {
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
		b, err := mountBundle(name, img, hash, fw.VerityHash)
		if err != nil {
			Logf("firmware bundle %s %v, skipped", name, err)
			continue
		}
		if data, err := os.ReadFile(b.mnt + "/.overlay"); err == nil {
			target, version, ok := parseOverlay(string(data))
			if !ok || !overlayWanted(NewRoot, target, version) {
				Logf("overlay bundle %s not newer than the system or invalid, skipped", name)
				b.release()
				continue
			}
			b.target, b.version = target, version
			if old := overlays[target]; old != nil {
				if old.version >= version {
					Logf("overlay bundle %s superseded by %s, skipped", name, old.name)
					b.release()
					continue
				}
				Logf("overlay bundle %s superseded by %s, skipped", old.name, name)
				old.release()
			}
			overlays[target] = b
			continue
		}
		abi, driver := readABI(b.mnt + "/.kernel-abi")
		if driver && abi != release {
			Logf("driver bundle %s built for kernel %s != running %s, skipped", name, abi, release)
			b.release()
			continue
		}
		if driver {
			Logf("driver bundle %s verified + mounted (kernel %s, activated post-boot)", name, abi)
			continue
		}
		firmware = append([]*mountedBundle{b}, firmware...)
		Logf("firmware bundle %s verified + mounted (anchor-verified)", name)
	}
	for _, b := range overlays {
		applyOverlay(b)
	}
	unionFirmware(firmware)
}

func bundleDirs(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, filepath.Join(root, e.Name()))
		}
	}
	return dirs
}

type mountedBundle struct {
	name    string
	mapper  string
	loops   []string
	mnt     string
	target  string
	version uint64
}

func mountBundle(name, img, hash, rootHash string) (*mountedBundle, error) {
	b := &mountedBundle{name: name, mapper: name + "-fwverity"}
	dl, err := AttachLoop(img)
	if err != nil {
		return nil, errors.New("attach failed")
	}
	b.loops = append(b.loops, dl)
	hl, err := AttachLoop(hash)
	if err != nil {
		b.release()
		return nil, errors.New("hash attach failed")
	}
	b.loops = append(b.loops, hl)
	node, err := OpenVerity(b.mapper, dl, hl, rootHash)
	if err != nil || !HasEROFS(node) {
		b.release()
		return nil, errors.New("verity failed")
	}
	mnt := NewRoot + "/var/.fw-" + name
	if Mount(node, mnt, "erofs", syscall.MS_RDONLY, "") != nil {
		b.release()
		return nil, errors.New("mount failed")
	}
	b.mnt = mnt
	return b, nil
}

func (b *mountedBundle) release() {
	if b.mnt != "" {
		Unmount(b.mnt)
	}
	CloseVerity(b.mapper)
	for _, l := range b.loops {
		DetachLoop(l)
	}
}

func unionFirmware(bundles []*mountedBundle) {
	if len(bundles) == 0 {
		Logf("no firmware bundle mounted, base firmware only")
		return
	}
	lowers := make([]string, 0, len(bundles))
	for _, b := range bundles {
		lowers = append(lowers, b.mnt)
	}
	base := NewRoot + "/var/.base-firmware"
	release := func() {
		for _, b := range bundles {
			b.release()
		}
	}
	if Bind(NewRoot+"/usr/lib/firmware", base) != nil {
		Logf("firmware base bind failed, base only")
		release()
		return
	}
	opts := "lowerdir=" + strings.Join(lowers, ":") + ":" + base
	if syscall.Mount("overlay", NewRoot+"/usr/lib/firmware", "overlay", syscall.MS_RDONLY, opts) == nil {
		Logf("firmware add-on bundles unioned over base firmware")
		return
	}
	Logf("firmware overlay failed, using base firmware")
	Unmount(base)
	release()
}

func applyOverlay(b *mountedBundle) {
	base := NewRoot + "/var/.base-" + b.name
	if Bind(NewRoot+b.target, base) != nil {
		Logf("overlay bundle %s base bind failed, skipped", b.name)
		b.release()
		return
	}
	opts := "lowerdir=" + b.mnt + ":" + base
	if err := syscall.Mount("overlay", NewRoot+b.target, "overlay", syscall.MS_RDONLY, opts); err != nil {
		Logf("overlay bundle %s mount failed (%v), skipped", b.name, err)
		Unmount(base)
		b.release()
		return
	}
	Logf("overlay bundle %s version %d mounted over %s", b.name, b.version, b.target)
}

func parseOverlay(data string) (string, uint64, bool) {
	var target string
	var version uint64
	for _, line := range strings.Split(data, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch key {
		case "target":
			target = value
		case "version":
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return "", 0, false
			}
			version = v
		}
	}
	if version == 0 || target != filepath.Clean(target) || !strings.HasPrefix(target, "/usr/") || target == "/usr/lib/firmware" {
		return "", 0, false
	}
	return target, version, true
}

func overlayWanted(root, target string, version uint64) bool {
	fi, err := os.Lstat(root + target)
	if err != nil || !fi.IsDir() {
		return false
	}
	data, err := os.ReadFile(root + target + "/.overlay-version")
	if err != nil {
		return true
	}
	base, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return false
	}
	return version > base
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
