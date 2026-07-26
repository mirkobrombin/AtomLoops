// initramfs-main is the initramfs init for the AtomLoops STANDALONE build path
// (scripts/build/fetch-release.sh -> scripts/boot/initramfs-build.sh ->
// build-kernelcache.sh), used to build and test the OTA kernelcache on its own.
//
// IT IS NOT THE INITRAMFS SHIPPED IN THE SINTY RC IMAGE. The Sinty buildroot image
// bakes singularity-os/scripts/build-initramfs.sh (busybox shell init) into the UKI
// via package.sh -- THAT is the canonical RC initramfs. E2E bug 6: an f2fs /var
// mount fix applied here did NOT reach the RC because the RC uses the shell one.
// KEEP THE TWO IN LOCKSTEP: any boot-chain change (var-mount fstype, verity, slot
// selection) must be applied to BOTH this file and build-initramfs.sh.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type Deployment struct {
	RootFS struct {
		Current       string `json:"current"`
		Pending       string `json:"pending"`
		Rollback      string `json:"rollback"`
		BootAttempts  int    `json:"boot_attempts"`
		MaxAttempts   int    `json:"max_attempts"`
		LastKnownGood string `json:"last_known_good"`
	} `json:"rootfs"`
	KernelCache struct {
		State           string `json:"state"`
		StableBoots     int    `json:"stable_boots"`
		StableThreshold int    `json:"stable_threshold"`
		Format          string `json:"format"`
	} `json:"kernelcache"`
	Security struct {
		Level      int  `json:"level"`
		DmVerity   bool `json:"dm_verity"`
		SecureBoot bool `json:"secure_boot"`
	} `json:"security"`
}

const sysFinitModule = 313

func insmod(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	param := []byte{0}
	_, _, errno := syscall.Syscall(sysFinitModule, f.Fd(),
		uintptr(unsafe.Pointer(&param[0])), 0)
	if errno != 0 && errno != syscall.EEXIST {
		fmt.Fprintf(os.Stderr, "[init] finit_module %s: %v\n", path, errno)
	} else {
		fmt.Printf("[init] loaded %s\n", path)
	}
}

func loadKernelModules() {
	modDir := "/lib/modules"
	entries, err := os.ReadDir(modDir)
	if err != nil || len(entries) == 0 {
		fmt.Println("[init] no kernel modules dir found")
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		modPath := modDir + "/" + entry.Name()
		mods := []string{
			modPath + "/virtio.ko",
			modPath + "/virtio_ring.ko",
			modPath + "/virtio_mmio.ko",
			modPath + "/virtio_pci_modern_dev.ko",
			modPath + "/virtio_pci_legacy_dev.ko",
			modPath + "/virtio_pci.ko",
			modPath + "/virtio_blk.ko",
			modPath + "/loop.ko",
			modPath + "/crc32c_generic.ko",
			modPath + "/libcrc32c.ko",
			modPath + "/reed_solomon.ko",
			modPath + "/dm-mod.ko",
			modPath + "/dm-bufio.ko",
			modPath + "/xxhash_generic.ko",
			modPath + "/dm-verity.ko",
			modPath + "/erofs.ko",
			modPath + "/overlay.ko",
			modPath + "/crc16.ko",
			modPath + "/mbcache.ko",
			modPath + "/jbd2.ko",
			modPath + "/ext4.ko",
		}
		for _, m := range mods {
			insmod(m)
		}
	}
}

// cmdlineValue returns the value of key=... in a kernel cmdline, or "" if the key
// is absent. Isolated from the /proc read so the verity-gate parse is testable.
func cmdlineValue(cmdline, key string) string {
	prefix := key + "="
	for _, field := range strings.Fields(cmdline) {
		if strings.HasPrefix(field, prefix) {
			return strings.TrimPrefix(field, prefix)
		}
	}
	return ""
}

func findRootHash() string {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	return cmdlineValue(string(data), "ATOM_ROOT_HASH")
}

// firmwareRootHash returns the dm-verity root hash the firmware add-on image must
// match, taken from the signed kernel cmdline (ATOM_FIRMWARE_HASH), or "" when no
// firmware track is in play.
func firmwareRootHash() string {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	return cmdlineValue(string(data), "ATOM_FIRMWARE_HASH")
}

func devCandidates() []string {
	var out []string
	for _, b := range []string{
		"/dev/vda", "/dev/vdb", "/dev/vdc", "/dev/vdd",
		"/dev/sda", "/dev/sdb", "/dev/sdc", "/dev/sdd",
		"/dev/nvme0n1", "/dev/mmcblk0",
	} {
		out = append(out, b)
		for i := 1; i <= 4; i++ {
			out = append(out, fmt.Sprintf("%s%d", b, i))
			out = append(out, fmt.Sprintf("%sp%d", b, i))
		}
	}
	return out
}

func losetupBin() string {
	if _, err := os.Stat("/sbin/losetup"); err == nil {
		return "/sbin/losetup"
	}
	return "/bin/losetup"
}

func loopAttach(file string) string {
	bin := losetupBin()
	out, err := exec.Command(bin, "-f").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[init] losetup -f: %v\n", err)
		return ""
	}
	loop := strings.TrimSpace(string(out))
	if o, err := exec.Command(bin, "-r", loop, file).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "[init] losetup %s -> %s: %v %s\n", file, loop, err, strings.TrimSpace(string(o)))
		return ""
	}
	fmt.Printf("[init] %s -> %s\n", file, loop)
	return loop
}

func mountSystem() (string, string, bool) {
	target := "/sysdata"
	os.MkdirAll(target, 0755)
	for _, dev := range devCandidates() {
		if _, err := os.Stat(dev); err != nil {
			continue
		}
		if syscall.Mount(dev, target, "ext4", syscall.MS_RDONLY, "") != nil {
			continue
		}
		if _, err := os.Stat(target + "/boot/rootfs/rootfs-active.erofs"); err == nil {
			fmt.Printf("[init] system partition: %s\n", dev)
			return target, dev, true
		}
		syscall.Unmount(target, 0)
	}
	return "", "", false
}

// parentDisk returns the whole-disk device (e.g. /dev/nvme0n1) that dev is a
// partition of, resolved via sysfs. It is empty when dev is not a partition or
// cannot be resolved, which the caller treats as "do not touch this device."
func parentDisk(dev string) string {
	real, err := filepath.EvalSymlinks("/sys/class/block/" + filepath.Base(dev))
	if err != nil {
		return ""
	}
	parent := filepath.Base(filepath.Dir(real))
	if parent == "" || parent == "block" {
		return ""
	}
	if _, err := os.Stat("/sys/class/block/" + parent); err != nil {
		return ""
	}
	return "/dev/" + parent
}

// verityFail aborts the boot CLOSED when the root image fails dm-verity. It must NOT
// fall back to the raw unverified device: a verity failure on a signed boot means the
// rootfs was tampered with or corrupted, and mounting it anyway defeats the entire
// verified-boot chain (loader Ed25519 -> UKI -> dm-verity root). Powers off so a
// tampered system never boots.
func verityFail(reason string) {
	fmt.Fprintf(os.Stderr, "\n[init] FATAL: root image failed dm-verity (%s).\n", reason)
	fmt.Fprintln(os.Stderr, "[init] Refusing to mount a possibly-tampered rootfs. Powering off.")
	syscall.Sync()
	time.Sleep(3 * time.Second) // let the message reach the console
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	select {} // unreachable: the machine is powering off
}

func setupVerity(sysMount string) string {
	erofsFile := sysMount + "/boot/rootfs/rootfs-active.erofs"
	hashFile := sysMount + "/boot/rootfs/rootfs-active.hash"

	dataLoop := loopAttach(erofsFile)
	if dataLoop == "" {
		return ""
	}

	rootHash := findRootHash()
	if rootHash == "" || rootHash == "pending" {
		fmt.Println("[init] ATOM_ROOT_HASH not set, mounting rootfs without dm-verity")
		return dataLoop
	}
	fmt.Printf("[init] root_hash: %s\n", rootHash)

	// Bootloader-unlock escape hatch: a device the owner deliberately unlocked in
	// recovery has its verity toggle turned off in the TPM. Honor that here, but
	// ONLY when the TPM asserts BOTH facts (lock bit unlocked AND verity off). This
	// is the single path that skips verity with a hash present, so it fails closed:
	// a missing sintykey, an unreachable TPM, or either fact reading locked/on keeps
	// full dm-verity enforcement.
	if verityDisabledByUnlock() {
		// Persistent per-boot notice: an unlocked device warns every time it boots.
		fmt.Println("[init] ==================================================================")
		fmt.Println("[init]  DEVICE UNLOCKED - verified boot is OFF, this system is not sealed")
		fmt.Println("[init]  mounting the root image without dm-verity")
		fmt.Println("[init] ==================================================================")
		return dataLoop
	}

	if _, err := os.Stat("/sbin/veritysetup"); err != nil {
		fmt.Println("[init] veritysetup missing, mounting unverified")
		return dataLoop
	}
	hashLoop := loopAttach(hashFile)
	if hashLoop == "" {
		// a root hash is set but the hash tree can't be attached -> can't verify -> stop
		verityFail("hash device attach failed")
		return ""
	}

	cmd := exec.Command("/sbin/veritysetup", "open", dataLoop, "atom-verity", hashLoop, rootHash)
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH=/lib")
	if o, err := cmd.CombinedOutput(); err != nil {
		// open failure = hash mismatch = the rootfs was TAMPERED/corrupted. Fail CLOSED,
		// never fall back to the raw device.
		verityFail(fmt.Sprintf("veritysetup open failed: %v %s", err, strings.TrimSpace(string(o))))
		return ""
	}
	verityDev := "/dev/mapper/atom-verity"
	if _, err := os.Stat(verityDev); err != nil {
		verityFail(fmt.Sprintf("%s missing after open", verityDev))
		return ""
	}
	fmt.Printf("[init] dm-verity active on %s\n", verityDev)
	return verityDev
}

// sintykeyBinPath finds the crypto CLI that reads the TPM lock bit and verity
// toggle. If it is not in the initramfs, the reads below fail and the caller stays
// fully verity-enforced (fail closed).
func sintykeyBinPath() string {
	for _, p := range []string{"/sbin/sintykey", "/bin/sintykey", "/usr/bin/sintykey"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "sintykey"
}

// verityDisabledByUnlock reports whether this device was deliberately unlocked in
// recovery and therefore boots without dm-verity. It reads two independent facts
// from the TPM via sintykey and defers the decision to unlockGrantsNoVerity, which
// fails closed.
func verityDisabledByUnlock() bool {
	bin := sintykeyBinPath()
	lockOut, lockErr := exec.Command(bin, "lock-state").Output()
	verOut, verErr := exec.Command(bin, "verity-state").Output()
	return unlockGrantsNoVerity(string(lockOut), lockErr, string(verOut), verErr)
}

// unlockGrantsNoVerity is the pure fail-closed rule, isolated so it is unit-testable
// without a TPM. Skipping dm-verity is permitted ONLY when both sintykey reads
// succeeded and explicitly reported the device unlocked (locked=false) AND its
// verity toggle off (verity=off). Any read error, or either fact reading
// locked/on, keeps verity enforced.
func unlockGrantsNoVerity(lockOut string, lockErr error, verOut string, verErr error) bool {
	if lockErr != nil || verErr != nil {
		return false
	}
	return strings.Contains(lockOut, "locked=false") && strings.Contains(verOut, "verity=off")
}

// mountFirmware unions the optional signed firmware add-on image over the base
// firmware in the new root, before switch_root, so the kernel finds hardware
// firmware for the devices udev probes in the real system. It NEVER blocks boot:
// the survival firmware (wifi, display) is baked into the rootfs and stays visible
// underneath, so a missing, unverifiable, or unmountable firmware image degrades
// to base-only and the system still boots. A failed firmware update must never
// brick recovery.
//
// The lower layers are kept under the writable, persistent /var (they become
// /var/.firmware-* in the new root) so the overlay survives switch_root and is
// not shadowed: the read-only erofs rootfs cannot host mkdir'd mountpoints, and
// /run gets overmounted by a tmpfs after switch_root, which would hide them.
// The loop devices hold their backing files open even once /boot is gone.
func mountFirmware(rootMount, sysMount string) {
	img := sysMount + "/boot/firmware/firmware-active.img"
	hashFile := sysMount + "/boot/firmware/firmware-active.hash"
	if _, err := os.Stat(img); err != nil {
		return // no firmware track: the base survival firmware is enough
	}

	var loops []string
	verityOpen := false
	// A degraded firmware boot must not carry a dangling loop device or dm-verity
	// mapper across switch_root; the base survival firmware still boots without it.
	cleanup := func() {
		if verityOpen {
			exec.Command("/sbin/veritysetup", "close", "atom-fw-verity").Run()
		}
		bin := losetupBin()
		for _, l := range loops {
			exec.Command(bin, "-d", l).Run()
		}
	}

	dataLoop := loopAttach(img)
	if dataLoop == "" {
		fmt.Fprintln(os.Stderr, "[init] firmware image attach failed, using base firmware")
		return
	}
	loops = append(loops, dataLoop)
	dev := dataLoop

	// Verify the image against the signed cmdline hash. A mismatch means a
	// tampered or corrupt firmware image: do NOT mount it, but do NOT brick.
	if fwHash := firmwareRootHash(); fwHash != "" && fwHash != "pending" {
		if _, err := os.Stat("/sbin/veritysetup"); err == nil {
			hashLoop := loopAttach(hashFile)
			if hashLoop == "" {
				fmt.Fprintln(os.Stderr, "[init] firmware hash device attach failed, using base firmware")
				cleanup()
				return
			}
			loops = append(loops, hashLoop)
			cmd := exec.Command("/sbin/veritysetup", "open", dataLoop, "atom-fw-verity", hashLoop, fwHash)
			cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH=/lib")
			if o, err := cmd.CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "[init] firmware verity failed (%v %s), using base firmware\n",
					err, strings.TrimSpace(string(o)))
				cleanup()
				return
			}
			verityOpen = true
			dev = "/dev/mapper/atom-fw-verity"
			fmt.Println("[init] dm-verity active on firmware image")
		}
	}

	imgMount := rootMount + "/var/.firmware-img"
	baseSaved := rootMount + "/var/.base-firmware"
	base := rootMount + "/usr/lib/firmware"
	os.MkdirAll(imgMount, 0755)
	os.MkdirAll(baseSaved, 0755)
	if syscall.Mount(dev, imgMount, "erofs", syscall.MS_RDONLY, "") != nil {
		fmt.Fprintln(os.Stderr, "[init] firmware image mount failed, using base firmware")
		cleanup()
		return
	}
	// Capture the base firmware as a lower layer so it stays visible under the
	// add-on rather than being hidden by the overlay mounted on the same path.
	if syscall.Mount(base, baseSaved, "", syscall.MS_BIND, "") != nil {
		fmt.Fprintln(os.Stderr, "[init] firmware base bind failed, using base firmware")
		syscall.Unmount(imgMount, 0)
		cleanup()
		return
	}
	// Read-only union: the add-on takes precedence, the base is the fallback.
	opts := "lowerdir=" + imgMount + ":" + baseSaved
	if syscall.Mount("overlay", base, "overlay", syscall.MS_RDONLY, opts) != nil {
		fmt.Fprintln(os.Stderr, "[init] firmware overlay failed, using base firmware")
		syscall.Unmount(baseSaved, 0)
		syscall.Unmount(imgMount, 0)
		cleanup()
		return
	}
	fmt.Println("[init] firmware add-on unioned over base firmware in /usr/lib/firmware")
}

// mountVar mounts the persistent /var, but ONLY from a partition on the SAME
// physical disk as the verified root (rootDev). This is the isolation guarantee: a
// live USB boot must never mount the internal disk's /var, which holds the
// installed user's home, config and etc-upper. No same-disk /var means live mode,
// and the caller falls back to tmpfs. A .atom-var marker on another disk is
// deliberately ignored: the marker alone is not enough, it must be the root's disk.
func mountVar(rootMount, rootDev string) bool {
	disk := parentDisk(rootDev)
	if disk == "" {
		fmt.Fprintf(os.Stderr, "[init] cannot resolve root disk for %s, refusing cross-disk /var\n", rootDev)
		return false
	}
	target := rootMount + "/var"
	for _, dev := range devCandidates() {
		if parentDisk(dev) != disk {
			continue // never touch a partition on any other physical disk
		}
		if _, err := os.Stat(dev); err != nil {
			continue
		}
		// f2fs is the encrypted-data format (fscrypt); ext4 is kept for
		// transition/old images. syscall.Mount does not probe the fs, so try
		// each explicitly.
		mounted := false
		for _, fstype := range []string{"f2fs", "ext4"} {
			if syscall.Mount(dev, target, fstype, 0, "") == nil {
				mounted = true
				break
			}
		}
		if !mounted {
			continue
		}
		if _, err := os.Stat(target + "/.atom-var"); err == nil {
			fmt.Printf("[init] persistent /var: %s (same disk as root: %s)\n", dev, disk)
			return true
		}
		syscall.Unmount(target, 0)
	}
	return false
}

func dropToShell() {
	fmt.Println("[init] dropping to /bin/sh for debug")
	cmd := exec.Command("/bin/sh")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	time.Sleep(1 * time.Second)
	cmd.Run()
}

func readDeployment(path, backup string) (Deployment, error) {
	var d Deployment
	data, err := os.ReadFile(path)
	if err != nil {
		data, err = os.ReadFile(backup)
		if err != nil {
			return d, err
		}
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return d, err
	}
	return d, nil
}

func main() {
	fmt.Println("[init] Atom Loops initramfs starting (file-based rootfs)")

	syscall.Mount("proc", "/proc", "proc", 0, "")
	syscall.Mount("sysfs", "/sys", "sysfs", 0, "")
	syscall.Mount("devtmpfs", "/dev", "devtmpfs", 0, "")

	fmt.Println("[init] loading kernel modules")
	loadKernelModules()

	sysMount, sysDev, ok := mountSystem()
	if !ok {
		fmt.Fprintf(os.Stderr, "[init] no Atom Loops system partition found\n")
		dropToShell()
		return
	}

	d, err := readDeployment(sysMount+"/boot/rootfs/deployment.json",
		sysMount+"/boot/rootfs/deployment.json.bak")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[init] deployment.json: %v\n", err)
	} else {
		fmt.Printf("[init] current=%s pending=%s boot_attempts=%d/%d\n",
			d.RootFS.Current, d.RootFS.Pending, d.RootFS.BootAttempts, d.RootFS.MaxAttempts)
		if d.RootFS.Pending != "" {
			fmt.Println("[init] pending update present (PoC: atomic switch not yet applied)")
		}
	}

	verityDev := setupVerity(sysMount)
	if verityDev == "" {
		fmt.Fprintf(os.Stderr, "[init] could not prepare rootfs image\n")
		dropToShell()
		return
	}

	rootMount := "/newroot"
	os.MkdirAll(rootMount, 0755)
	if syscall.Mount(verityDev, rootMount, "erofs", syscall.MS_RDONLY, "") != nil {
		fmt.Fprintf(os.Stderr, "[init] mounting EROFS root failed\n")
		dropToShell()
		return
	}
	fmt.Printf("[init] mounted verified EROFS root on %s\n", rootMount)

	if mountVar(rootMount, sysDev) {
		os.MkdirAll(rootMount+"/var/etc-upper", 0755)
		os.MkdirAll(rootMount+"/var/etc-work", 0755)
		etcOpts := fmt.Sprintf("lowerdir=%s/etc,upperdir=%s/var/etc-upper,workdir=%s/var/etc-work",
			rootMount, rootMount, rootMount)
		if syscall.Mount("overlay", rootMount+"/etc", "overlay", 0, etcOpts) == nil {
			fmt.Println("[init] persistent overlay mounted on /etc (upper in /var)")
		} else {
			fmt.Fprintf(os.Stderr, "[init] /etc overlay failed (continuing with ro /etc)\n")
		}
	} else {
		fmt.Fprintf(os.Stderr, "[init] no persistent /var found, falling back to tmpfs /var\n")
		syscall.Mount("tmpfs", rootMount+"/var", "tmpfs", 0, "mode=0755")
	}

	if syscall.Mount("tmpfs", rootMount+"/tmp", "tmpfs", 0, "mode=1777") == nil {
		fmt.Println("[init] tmpfs mounted on /tmp")
	}

	os.MkdirAll(rootMount+"/var/home", 0755)
	if syscall.Mount(rootMount+"/var/home", rootMount+"/home", "", syscall.MS_BIND, "") != nil {
		fmt.Fprintf(os.Stderr, "[init] bind mount /home failed\n")
	} else {
		fmt.Println("[init] bind mounted /var/home to /home")
	}

	// Union the signed firmware add-on over the base firmware before switch_root,
	// so udev finds it when it probes hardware in the real system. Never blocks
	// boot: absent or bad firmware degrades to the base survival set.
	mountFirmware(rootMount, sysMount)

	for _, m := range []string{"/dev", "/proc", "/sys"} {
		target := rootMount + m
		os.MkdirAll(target, 0755)
		if syscall.Mount(m, target, "", syscall.MS_MOVE, "") != nil {
			fmt.Fprintf(os.Stderr, "[init] move %s failed\n", m)
		}
	}

	fmt.Println("[init] switching root")
	if err := syscall.Chroot(rootMount); err != nil {
		fmt.Fprintf(os.Stderr, "[init] chroot failed: %v\n", err)
		dropToShell()
		return
	}
	os.Chdir("/")

	for _, init := range []string{"/sbin/init", "/usr/lib/systemd/systemd", "/lib/systemd/systemd", "/bin/init"} {
		if fi, err := os.Stat(init); err == nil && !fi.IsDir() {
			fmt.Printf("[init] executing %s\n", init)
			syscall.Exec(init, []string{init}, os.Environ())
			fmt.Fprintf(os.Stderr, "[init] exec %s failed\n", init)
		}
	}

	fmt.Fprintf(os.Stderr, "[init] no init found\n")
	dropToShell()
}
