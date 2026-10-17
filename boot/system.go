package boot

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

// Cmdline holds the kernel command line split into words.
type Cmdline []string

// ReadCmdline reads /proc/cmdline.
func ReadCmdline() Cmdline {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return nil
	}
	return Cmdline(strings.Fields(string(data)))
}

// Value returns the value of key=value, or "" when key is absent. The first
// occurrence wins.
func (c Cmdline) Value(key string) string {
	prefix := key + "="
	for _, w := range c {
		if v, ok := strings.CutPrefix(w, prefix); ok {
			return v
		}
	}
	return ""
}

// Has reports whether the bare word, or word=1, is on the command line.
func (c Cmdline) Has(word string) bool {
	for _, w := range c {
		if w == word || w == word+"=1" {
			return true
		}
	}
	return false
}

// MountEarly mounts /proc, /sys and /dev, creates the device-mapper control
// node, and points standard input and output at the console.
func MountEarly() {
	os.MkdirAll("/proc", 0755)
	os.MkdirAll("/sys", 0755)
	os.MkdirAll("/dev", 0755)
	syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "")
	syscall.Mount("sysfs", "/sys", "sysfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "")
	syscall.Mount("devtmpfs", "/dev", "devtmpfs", syscall.MS_NOSUID, "mode=0755")
	LinkStandardDevices("/dev")
	if f, err := os.OpenFile("/dev/console", os.O_RDWR, 0); err == nil {
		for fd := 0; fd <= 2; fd++ {
			syscall.Dup3(int(f.Fd()), fd, 0)
		}
		f.Close()
	}
	os.MkdirAll("/dev/mapper", 0755)
	os.MkdirAll("/run", 0755)
	if _, err := os.Stat("/dev/mapper/control"); err != nil {
		if mm, err := os.ReadFile("/sys/class/misc/device-mapper/dev"); err == nil {
			var major, minor int
			if _, err := fmt.Sscanf(strings.TrimSpace(string(mm)), "%d:%d", &major, &minor); err == nil {
				syscall.Mknod("/dev/mapper/control", syscall.S_IFCHR|0600, major<<8|minor&0xff|(minor&^0xff)<<12)
			}
		}
	}
}

// LinkStandardDevices creates the links a devtmpfs does not carry: /dev/fd
// and the three standard streams, all resolved through /proc/self/fd.
// Existing entries are left alone.
func LinkStandardDevices(dev string) {
	links := [][2]string{
		{"fd", "/proc/self/fd"},
		{"stdin", "/proc/self/fd/0"},
		{"stdout", "/proc/self/fd/1"},
		{"stderr", "/proc/self/fd/2"},
	}
	for _, l := range links {
		os.Symlink(l[1], filepath.Join(dev, l[0]))
	}
}

// LoadModules loads the named kernel modules, in order, from
// /lib/modules/<release>. Modules that are missing or already loaded are
// skipped; the kernel may have them built in.
func LoadModules(names ...string) {
	dirs, _ := filepath.Glob("/lib/modules/*")
	for _, dir := range dirs {
		for _, name := range names {
			path := findModule(dir, name)
			if path == "" {
				continue
			}
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			param := []byte{0}
			_, _, errno := syscall.Syscall(sysFinitModule, f.Fd(), uintptr(unsafe.Pointer(&param[0])), 0)
			f.Close()
			if errno != 0 && errno != syscall.EEXIST {
				Logf("module %s: %v", name, errno)
			}
		}
	}
}

func findModule(dir, name string) string {
	var found string
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || found != "" {
			return nil
		}
		if !d.IsDir() && d.Name() == name+".ko" {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// Logf writes one line of init diagnostics to standard error.
func Logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[init] "+format+"\n", a...)
}

// Partition describes a block device as sysfs sees it.
type Partition struct {
	Dev      string
	Disk     string
	PartName string
	Label    string
}

// Partitions lists the partitions of every disk, and whole disks that carry
// no partition table, sorted by device path.
func Partitions() []Partition {
	entries, err := os.ReadDir("/sys/class/block")
	if err != nil {
		return nil
	}
	var out []Partition
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "zram") {
			continue
		}
		p := Partition{Dev: "/dev/" + name, Disk: DiskOf("/dev/" + name)}
		if _, err := os.Stat("/sys/class/block/" + name + "/partition"); err != nil {
			if hasPartitions(name) {
				continue
			}
		}
		p.PartName = ueventValue(name, "PARTNAME")
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dev < out[j].Dev })
	return out
}

func hasPartitions(disk string) bool {
	entries, err := os.ReadDir("/sys/class/block/" + disk)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), disk) {
			return true
		}
	}
	return false
}

func ueventValue(name, key string) string {
	f, err := os.Open("/sys/class/block/" + name + "/uevent")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), key+"="); ok {
			return v
		}
	}
	return ""
}

// DiskOf returns the whole disk a block device belongs to: the parent disk of
// a partition, or the device itself.
func DiskOf(dev string) string {
	name := filepath.Base(dev)
	if _, err := os.Stat("/sys/class/block/" + name + "/partition"); err != nil {
		return name
	}
	real, err := filepath.EvalSymlinks("/sys/class/block/" + name)
	if err != nil {
		return name
	}
	return filepath.Base(filepath.Dir(real))
}

// LoopBacking returns the file a loop device is bound to, or "".
func LoopBacking(dev string) string {
	data, err := os.ReadFile("/sys/class/block/" + filepath.Base(dev) + "/loop/backing_file")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// IsVerityHash reports whether a device starts with a verity superblock.
func IsVerityHash(dev string) bool {
	f, err := os.Open(dev)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [8]byte
	if _, err := f.ReadAt(magic[:], 0); err != nil {
		return false
	}
	return string(magic[:6]) == "verity"
}

// Mount mounts with a filesystem type and option string.
func Mount(src, dst, fstype string, flags uintptr, data string) error {
	os.MkdirAll(dst, 0755)
	if err := syscall.Mount(src, dst, fstype, flags, data); err != nil {
		return fmt.Errorf("mount %s on %s: %w", src, dst, err)
	}
	return nil
}

// Move moves a mount point.
func Move(src, dst string) error {
	return Mount(src, dst, "", syscall.MS_MOVE, "")
}

// Bind bind-mounts a directory.
func Bind(src, dst string) error {
	return Mount(src, dst, "", syscall.MS_BIND, "")
}

// Unmount unmounts, ignoring errors.
func Unmount(path string) {
	syscall.Unmount(path, 0)
}

// MountedFS returns the filesystem type mounted on path, or "".
func MountedFS(path string) string {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return ""
	}
	fstype := ""
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[1] == path {
			fstype = f[2]
		}
	}
	return fstype
}
