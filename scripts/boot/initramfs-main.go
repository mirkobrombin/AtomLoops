package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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

func mountSystem() (string, bool) {
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
			return target, true
		}
		syscall.Unmount(target, 0)
	}
	return "", false
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

	if _, err := os.Stat("/sbin/veritysetup"); err != nil {
		fmt.Println("[init] veritysetup missing, mounting unverified")
		return dataLoop
	}
	hashLoop := loopAttach(hashFile)
	if hashLoop == "" {
		return dataLoop
	}

	cmd := exec.Command("/sbin/veritysetup", "open", dataLoop, "atom-verity", hashLoop, rootHash)
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH=/lib")
	if o, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "[init] veritysetup open failed: %v %s\n", err, strings.TrimSpace(string(o)))
		return dataLoop
	}
	verityDev := "/dev/mapper/atom-verity"
	if _, err := os.Stat(verityDev); err != nil {
		fmt.Fprintf(os.Stderr, "[init] %s missing after open\n", verityDev)
		return dataLoop
	}
	fmt.Printf("[init] dm-verity active on %s\n", verityDev)
	return verityDev
}

func mountVar(rootMount string) bool {
	target := rootMount + "/var"
	for _, dev := range devCandidates() {
		if _, err := os.Stat(dev); err != nil {
			continue
		}
		if syscall.Mount(dev, target, "ext4", 0, "") != nil {
			continue
		}
		if _, err := os.Stat(target + "/.atom-var"); err == nil {
			fmt.Printf("[init] persistent /var: %s\n", dev)
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

	sysMount, ok := mountSystem()
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

	if mountVar(rootMount) {
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
