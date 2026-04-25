package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
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

var deployPath = "/boot/rootfs/deployment.json"
var backupPath = "/boot/rootfs/deployment.json.bak"

func insmod(path string) {
	if _, err := os.Stat(path); err != nil {
		return
	}
	insmodBin := "/sbin/insmod"
	if _, err := os.Stat(insmodBin); err != nil {
		insmodBin = "/bin/insmod"
	}
	cmd := exec.Command(insmodBin, path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[init] insmod %s: %v\n", path, err)
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
		}
		for _, m := range mods {
			insmod(m)
		}
	}
}

func findRootDevice() string {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	for _, field := range strings.Fields(string(data)) {
		if strings.HasPrefix(field, "root=") {
			dev := strings.TrimPrefix(field, "root=")
			if strings.HasPrefix(dev, "/dev/") {
				return dev
			}
			if strings.HasPrefix(dev, "UUID=") || strings.HasPrefix(dev, "LABEL=") {
				// return empty and use possibleRoot fallback.
				return ""
			}
		}
	}
	return ""
}

func findRootHash() string {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	for _, field := range strings.Fields(string(data)) {
		if strings.HasPrefix(field, "ATOM_ROOT_HASH=") {
			return strings.TrimPrefix(field, "ATOM_ROOT_HASH=")
		}
	}
	return ""
}

func possibleRoot() string {
	for _, dev := range []string{"/dev/vda", "/dev/sda", "/dev/hda"} {
		if _, err := os.Stat(dev); err == nil {
			return dev
		}
	}
	return ""
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

func runVeritySetup(dataDev string) string {
	rootHash := findRootHash()
	if rootHash == "" || rootHash == "pending" {
		fmt.Println("[init] ATOM_ROOT_HASH not set, skipping dm-verity")
		return dataDev
	}
	fmt.Printf("[init] root_hash from cmdline: %s\n", rootHash)

	hashFile := "/boot/rootfs/rootfs-v1.hash"
	if _, err := os.Stat(hashFile); err != nil {
		fmt.Fprintf(os.Stderr, "[init] hash tree not found at %s: %v\n", hashFile, err)
		return dataDev
	}

	verityBin := "/sbin/veritysetup"
	if _, err := os.Stat(verityBin); err != nil {
		fmt.Println("[init] veritysetup not found, mounting data device directly")
		return dataDev
	}
	fmt.Printf("[init] veritysetup found at %s\n", verityBin)

	// Set up a loop device for the hash tree file so veritysetup can use it
	// as a block device. Busybox losetup doesn't support --show, so we find
	// the next free loop device first, then attach.
	fmt.Printf("[init] setting up loop device for hash tree %s\n", hashFile)
	losetupBin := "/bin/losetup"
	if _, err := os.Stat(losetupBin); err != nil {
		losetupBin = "/sbin/losetup"
	}

	out, err := exec.Command(losetupBin, "-f").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[init] losetup -f failed: %v\n", err)
		return dataDev
	}
	loopDev := strings.TrimSpace(string(out))
	fmt.Printf("[init] next free loop device: %s (using %s)\n", loopDev, losetupBin)

	attachOut, err := exec.Command(losetupBin, "-r", loopDev, hashFile).CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[init] losetup attach failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "[init] losetup output: %s\n", strings.TrimSpace(string(attachOut)))
		return dataDev
	}
	if len(attachOut) > 0 {
		fmt.Printf("[init] losetup output: %s\n", strings.TrimSpace(string(attachOut)))
	}
	fmt.Printf("[init] hash tree loop device: %s\n", loopDev)

	var cmd *exec.Cmd
	fmt.Printf("[init] running veritysetup open %s atom-verity %s %s\n", dataDev, loopDev, rootHash)
	cmd = exec.Command(verityBin, "open", dataDev, "atom-verity", loopDev, rootHash)
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH=/lib")
	vOut, vErr := cmd.CombinedOutput()
	if len(vOut) > 0 {
		fmt.Printf("[init] veritysetup output: %s\n", strings.TrimSpace(string(vOut)))
	}
	if vErr != nil {
		fmt.Fprintf(os.Stderr, "[init] veritysetup open failed: %v\n", vErr)
		fmt.Println("[init] falling back to direct mount (unverified)")
		exec.Command(losetupBin, "-d", loopDev).Run()
		return dataDev
	}

	verityDev := "/dev/mapper/atom-verity"
	if _, err := os.Stat(verityDev); err != nil {
		fmt.Fprintf(os.Stderr, "[init] dm-verity device %s not found: %v\n", verityDev, err)
		exec.Command(losetupBin, "-d", loopDev).Run()
		return dataDev
	}
	fmt.Printf("[init] dm-verity active on %s\n", verityDev)
	return verityDev
}

func readDeployment() (Deployment, error) {
	var d Deployment
	data, err := os.ReadFile(deployPath)
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(data, &d); err != nil {
		data, err = os.ReadFile(backupPath)
		if err != nil {
			return d, err
		}
		if err := json.Unmarshal(data, &d); err != nil {
			return d, err
		}
	}
	return d, nil
}

func main() {
	fmt.Println("[init] Atom Loops initramfs starting")

	// Mount basic virtual filesystems.
	fmt.Println("[init] mounting virtual filesystems")
	syscall.Mount("proc", "/proc", "proc", 0, "")
	syscall.Mount("sysfs", "/sys", "sysfs", 0, "")
	syscall.Mount("devtmpfs", "/dev", "devtmpfs", 0, "")

	// Load kernel modules for virtio and erofs support in QEMU.
	fmt.Println("[init] loading kernel modules")
	loadKernelModules()

	// Find root device.
	rootDev := findRootDevice()
	if rootDev == "" {
		rootDev = possibleRoot()
	}
	if rootDev == "" {
		fmt.Fprintf(os.Stderr, "[init] no root device found\n")
		dropToShell()
		return
	}
	fmt.Printf("[init] root device candidate: %s\n", rootDev)

	// Activate dm-verity if a hash device exists.
	// The hash device is expected to be rootDev with suffix ".hash".
	verityDev := runVeritySetup(rootDev)
	fmt.Printf("[init] using verified device: %s\n", verityDev)

	// Try to mount rootfs (EROFS preferred).
	rootMount := "/newroot"
	os.MkdirAll(rootMount, 0755)

	mounted := false
	for _, fs := range []string{"erofs", "ext4"} {
		if syscall.Mount(verityDev, rootMount, fs, syscall.MS_RDONLY, "") == nil {
			fmt.Printf("[init] mounted %s on %s as %s\n", verityDev, rootMount, fs)
			mounted = true
			break
		} else {
			fmt.Fprintf(os.Stderr, "[init] mount %s as %s failed\n", verityDev, fs)
		}
	}

	if !mounted {
		fmt.Fprintf(os.Stderr, "[init] no rootfs mounted, dropping to shell for debug\n")
		dropToShell()
		return
	}

	overlayMount := "/newroot-overlay"
	os.MkdirAll(overlayMount, 0755)
	os.MkdirAll("/overlay", 0755)
	if syscall.Mount("tmpfs", "/overlay", "tmpfs", 0, "size=128M") == nil {
		os.MkdirAll("/overlay/upper", 0755)
		os.MkdirAll("/overlay/work", 0755)
		opts := fmt.Sprintf("lowerdir=%s,upperdir=/overlay/upper,workdir=/overlay/work", rootMount)
		if syscall.Mount("overlay", overlayMount, "overlay", 0, opts) == nil {
			fmt.Printf("[init] overlayfs mounted on %s (lower=%s)\n", overlayMount, rootMount)
			rootMount = overlayMount
		} else {
			fmt.Fprintf(os.Stderr, "[init] overlay mount failed, using ro EROFS directly\n")
		}
	} else {
		fmt.Fprintf(os.Stderr, "[init] tmpfs for overlay failed, using ro EROFS\n")
	}

	// Read deployment WAL from the mounted rootfs.
	deployPath = rootMount + "/boot/rootfs/deployment.json"
	backupPath = rootMount + "/boot/rootfs/deployment.json.bak"
	d, err := readDeployment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[init] failed to read deployment: %v\n", err)
	} else {
		fmt.Printf("[init] current=%s pending=%s boot_attempts=%d/%d\n",
			d.RootFS.Current, d.RootFS.Pending,
			d.RootFS.BootAttempts, d.RootFS.MaxAttempts)

		if d.RootFS.Pending != "" {
			fmt.Println("[init] pending update found (PoC: skipping atomic switch)")
		}
		if d.RootFS.BootAttempts >= d.RootFS.MaxAttempts && d.RootFS.Rollback != "" {
			fmt.Println("[init] rollback would be triggered here")
		}
	}

	// Bind mount /var/home to /home.
	os.MkdirAll(rootMount+"/var/home", 0755)
	os.MkdirAll(rootMount+"/home", 0755)
	if syscall.Mount(rootMount+"/var/home", rootMount+"/home", "", syscall.MS_BIND, "") != nil {
		fmt.Fprintf(os.Stderr, "[init] bind mount /home failed\n")
	} else {
		fmt.Println("[init] bind mounted /var/home to /home")
	}

	// Move virtual fs into newroot.
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

	// Look for init in order of preference.
	candidates := []string{"/usr/bin/runit-init", "/sbin/init", "/bin/init", "/etc/init", "/linuxrc"}
	for _, init := range candidates {
		if fi, err := os.Stat(init); err == nil && !fi.IsDir() {
			fmt.Printf("[init] executing %s\n", init)
			syscall.Exec(init, []string{init}, os.Environ())
			fmt.Fprintf(os.Stderr, "[init] exec %s failed\n", init)
		}
	}

	fmt.Fprintf(os.Stderr, "[init] no init found\n")
	dropToShell()
}
