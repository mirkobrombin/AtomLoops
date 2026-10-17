package boot

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// DeviceUnlocked asks sintykey whether the owner unlocked the bootloader and
// turned dm-verity off. It fails closed: a missing tool, an unreachable TPM
// or either answer reading locked or on keeps verified boot.
func DeviceUnlocked(sintykey string) bool {
	lock, lockErr := exec.Command(sintykey, "lock-state").Output()
	ver, verErr := exec.Command(sintykey, "verity-state").Output()
	return UnlockGrantsNoVerity(string(lock), lockErr, string(ver), verErr)
}

// UnlockGrantsNoVerity is the rule DeviceUnlocked applies: verity may be
// skipped only when both reads succeeded and report the device unlocked and
// verity off.
func UnlockGrantsNoVerity(lockOut string, lockErr error, verOut string, verErr error) bool {
	if lockErr != nil || verErr != nil {
		return false
	}
	return strings.Contains(lockOut, "locked=false") && strings.Contains(verOut, "verity=off")
}

// Halt syncs and powers the machine off, and never returns.
func Halt() {
	syscall.Sync()
	time.Sleep(2 * time.Second)
	syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	for {
		time.Sleep(time.Minute)
	}
}

// Ext4Label returns the volume label of an ext4 filesystem, or "".
func Ext4Label(dev string) string {
	f, err := os.Open(dev)
	if err != nil {
		return ""
	}
	defer f.Close()
	sb := make([]byte, 1024)
	if _, err := f.ReadAt(sb, 1024); err != nil {
		return ""
	}
	if binary.LittleEndian.Uint16(sb[0x38:]) != 0xEF53 {
		return ""
	}
	return string(bytes.TrimRight(sb[0x78:0x88], "\x00"))
}

// SaveDiagnostics writes text as name on the first ext4 partition labelled
// label, replacing any earlier copy atomically and readable only by root. It
// reports whether the text reached a disk.
func SaveDiagnostics(label, name, text string) bool {
	dir := "/run/" + strings.ToLower(label)
	for _, p := range Partitions() {
		if Ext4Label(p.Dev) != label {
			continue
		}
		if Mount(p.Dev, dir, "ext4", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "") != nil {
			continue
		}
		tmp := fmt.Sprintf("%s/.%s.%d", dir, name, os.Getpid())
		os.Remove(tmp)
		err := os.WriteFile(tmp, []byte(text), 0o600)
		if err == nil {
			err = os.Rename(tmp, dir+"/"+name)
		}
		os.Remove(tmp)
		syscall.Sync()
		Unmount(dir)
		if err == nil {
			return true
		}
	}
	return false
}

// Rescue ends a boot that cannot continue. A locked device powers off. An
// unlocked one offers a root shell, but only after the person at the console
// types the confirmation phrase.
func Rescue(reason string, unlocked bool, shell string) {
	fmt.Fprintf(os.Stderr, "initramfs: %s\n", reason)
	if !unlocked {
		fmt.Fprintln(os.Stderr, "device locked: refusing a rescue shell")
		Halt()
	}
	fmt.Fprintln(os.Stderr, "DEVICE UNLOCKED. Type OPEN DEBUG SHELL to start a root shell:")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if !DebugShellConfirmed(line) {
		fmt.Fprintln(os.Stderr, "rescue shell confirmation denied")
		Halt()
	}
	fmt.Fprintln(os.Stderr, "starting confirmed rescue shell")
	cmd := exec.Command(shell)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Run()
	Halt()
}

// DebugShellConfirmed reports whether the typed line is the exact phrase.
func DebugShellConfirmed(line string) bool {
	return strings.TrimRight(line, "\r\n") == "OPEN DEBUG SHELL"
}

const (
	ramfsMagic = 0x858458f6
	tmpfsMagic = 0x01021994
)

// SwitchRoot frees the initramfs, moves /dev, /proc, /sys and /run into
// NewRoot, makes NewRoot the root and runs init there. It only returns when
// that fails.
func SwitchRoot(init string, args []string) error {
	var rootSt, newSt syscall.Stat_t
	if err := syscall.Stat("/", &rootSt); err != nil {
		return err
	}
	if err := syscall.Stat(NewRoot, &newSt); err != nil {
		return err
	}
	if rootSt.Dev == newSt.Dev {
		return fmt.Errorf("%s is not a separate mount", NewRoot)
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/", &fs); err != nil {
		return err
	}
	if fs.Type != ramfsMagic && fs.Type != tmpfsMagic {
		return fmt.Errorf("the current root is not an initramfs")
	}
	for _, m := range []string{"/dev", "/proc", "/sys", "/run"} {
		if MountedFS(m) == "" {
			continue
		}
		if err := Move(m, NewRoot+m); err != nil {
			Unmount(m)
		}
	}
	if err := syscall.Chdir(NewRoot); err != nil {
		return err
	}
	removeContents("/", rootSt.Dev)
	if err := syscall.Mount(".", "/", "", syscall.MS_MOVE, ""); err != nil {
		return err
	}
	if err := syscall.Chroot("."); err != nil {
		return err
	}
	if err := syscall.Chdir("/"); err != nil {
		return err
	}
	return syscall.Exec(init, append([]string{init}, args...), os.Environ())
}

func removeContents(dir string, dev uint64) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		path := strings.TrimSuffix(dir, "/") + "/" + e.Name()
		var st syscall.Stat_t
		if syscall.Lstat(path, &st) != nil || st.Dev != dev {
			continue
		}
		if st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
			removeContents(path, dev)
			syscall.Rmdir(path)
			continue
		}
		syscall.Unlink(path)
	}
}
