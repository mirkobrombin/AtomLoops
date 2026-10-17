package boot

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goodHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestCmdline(t *testing.T) {
	c := Cmdline(strings.Fields("ro quiet sing.roothash=abc sing.live=1 sinit.debug init=/x sing.roothash=second"))
	if got := c.Value("sing.roothash"); got != "abc" {
		t.Errorf("Value = %q, want the first occurrence", got)
	}
	if c.Value("sing.root") != "" {
		t.Error("a key prefix must not match")
	}
	if !c.Has("sing.live") || !c.Has("sinit.debug") || c.Has("sing.portable") {
		t.Error("Has misreports words")
	}
}

func superblock(version, hashType uint32, alg string, data, hash uint32, blocks uint64, salt []byte) []byte {
	buf := make([]byte, 512)
	copy(buf, "verity\x00\x00")
	le := binary.LittleEndian
	le.PutUint32(buf[8:], version)
	le.PutUint32(buf[12:], hashType)
	copy(buf[32:], alg)
	le.PutUint32(buf[64:], data)
	le.PutUint32(buf[68:], hash)
	le.PutUint64(buf[72:], blocks)
	le.PutUint16(buf[80:], uint16(len(salt)))
	copy(buf[88:], salt)
	return buf
}

func TestVeritySuperblockAndTable(t *testing.T) {
	sb, err := ParseVeritySuperblock(superblock(1, 1, "sha256", 4096, 4096, 1000, []byte{0xaa, 0xbb}))
	if err != nil {
		t.Fatal(err)
	}
	got := VerityTable(sb, "7:0", "7:1", strings.ToUpper(goodHash))
	want := "1 7:0 7:1 4096 4096 1000 1 sha256 " + goodHash + " aabb"
	if got != want {
		t.Errorf("table\n got %q\nwant %q", got, want)
	}
	sb, _ = ParseVeritySuperblock(superblock(1, 1, "sha256", 4096, 4096, 1, nil))
	if !strings.HasSuffix(VerityTable(sb, "a", "b", goodHash), " -") {
		t.Error("an empty salt must be written as -")
	}
	bad := map[string][]byte{
		"magic":      append([]byte("notverit"), make([]byte, 504)...),
		"version":    superblock(2, 1, "sha256", 4096, 4096, 1, nil),
		"hash type":  superblock(1, 0, "sha256", 4096, 4096, 1, nil),
		"algorithm":  superblock(1, 1, "sha1", 4096, 4096, 1, nil),
		"block size": superblock(1, 1, "sha256", 4095, 4096, 1, nil),
		"no blocks":  superblock(1, 1, "sha256", 4096, 4096, 0, nil),
		"short":      []byte("verity"),
	}
	for name, buf := range bad {
		if _, err := ParseVeritySuperblock(buf); err == nil {
			t.Errorf("%s: accepted an invalid superblock", name)
		}
	}
}

func TestValidRootHash(t *testing.T) {
	for h, want := range map[string]bool{goodHash: true, goodHash[:62]: false, "": false, strings.Repeat("zz", 32): false} {
		if ValidRootHash(h) != want {
			t.Errorf("ValidRootHash(%q) != %v", h, want)
		}
	}
}

func TestUnlockRuleFailsClosed(t *testing.T) {
	e := errors.New("tpm")
	cases := []struct {
		lock, ver string
		lockErr   error
		verErr    error
		want      bool
	}{
		{"locked=false", "verity=off", nil, nil, true},
		{"locked=true", "verity=off", nil, nil, false},
		{"locked=false", "verity=on", nil, nil, false},
		{"locked=false", "verity=off", e, nil, false},
		{"locked=false", "verity=off", nil, e, false},
		{"", "", nil, nil, false},
	}
	for _, c := range cases {
		if got := UnlockGrantsNoVerity(c.lock, c.lockErr, c.ver, c.verErr); got != c.want {
			t.Errorf("%+v: got %v", c, got)
		}
	}
}

func TestDebugShellConfirmation(t *testing.T) {
	if !DebugShellConfirmed("OPEN DEBUG SHELL\n") || DebugShellConfirmed("open debug shell\n") || DebugShellConfirmed(" OPEN DEBUG SHELL\n") || DebugShellConfirmed("") {
		t.Error("the confirmation phrase must match exactly")
	}
}

type fakeDisk struct {
	parts    []Partition
	files    map[string]bool
	erofs    map[string]bool
	hashes   map[string]bool
	match    map[[2]string]bool
	isoFiles bool
	attached map[string]string
	mapped   map[string]bool
	unmount  error
	sleeps   int
}

func newFake() *fakeDisk {
	return &fakeDisk{
		files:    map[string]bool{},
		erofs:    map[string]bool{},
		hashes:   map[string]bool{},
		match:    map[[2]string]bool{},
		attached: map[string]string{},
		mapped:   map[string]bool{},
	}
}

func (f *fakeDisk) ops() Ops {
	n := 0
	return Ops{
		Partitions: func() []Partition { return f.parts },
		MountData: func(dev, dir string) bool {
			return f.files[dev+":data"]
		},
		Unmount: func(string) error { return f.unmount },
		Glob: func(p string) []string {
			var out []string
			for name := range f.files {
				if strings.HasPrefix(name, "/sysdata/boot/rootfs/") && strings.HasSuffix(name, p[strings.LastIndex(p, "."):]) {
					out = append(out, name)
				}
			}
			return sorted(out)
		},
		Exists: func(p string) bool { return f.files[p] || (f.isoFiles && strings.HasPrefix(p, "/isomedia/live/")) },
		AttachLoop: func(file string) (string, error) {
			n++
			dev := "/dev/loop" + string(rune('0'+n))
			f.attached[dev] = file
			return dev, nil
		},
		DetachLoop: func(dev string) error { delete(f.attached, dev); return nil },
		OpenVerity: func(name, data, hash, root string) (string, error) {
			if f.mapped[name] {
				return "", errors.New("busy")
			}
			f.mapped[name] = true
			if f.match[[2]string{f.backing(data), f.backing(hash)}] && root == goodHash {
				return "/dev/mapper/" + name + "+ok", nil
			}
			return "/dev/mapper/" + name, nil
		},
		CloseVerity:  func(name string) error { delete(f.mapped, name); return nil },
		HasEROFS:     func(dev string) bool { return strings.HasSuffix(dev, "+ok") || f.erofs[f.backing(dev)] },
		IsVerityHash: func(dev string) bool { return f.hashes[dev] },
		MountISO:     func(dev, dir string) bool { return f.files[dev+":iso"] },
		DiskOf: func(dev string) string {
			for _, p := range f.parts {
				if p.Dev == dev {
					return p.Disk
				}
			}
			return dev
		},
		Sleep: func(time.Duration) { f.sleeps++ },
	}
}

func (f *fakeDisk) backing(dev string) string {
	if file, ok := f.attached[dev]; ok {
		return file
	}
	return dev
}

func sorted(in []string) []string {
	for i := range in {
		for j := i + 1; j < len(in); j++ {
			if in[j] < in[i] {
				in[i], in[j] = in[j], in[i]
			}
		}
	}
	return in
}

func installed() *fakeDisk {
	f := newFake()
	f.parts = []Partition{{Dev: "/dev/nvme0n1p1", Disk: "nvme0n1"}, {Dev: "/dev/nvme0n1p2", Disk: "nvme0n1"}}
	f.files["/dev/nvme0n1p2:data"] = true
	for _, s := range []string{"active", "next"} {
		f.files["/sysdata/boot/rootfs/rootfs-"+s+".erofs"] = true
		f.files["/sysdata/boot/rootfs/rootfs-"+s+".hash"] = true
	}
	return f
}

func TestInstalledPicksTheSlotTheHashSigns(t *testing.T) {
	f := installed()
	f.match[[2]string{"/sysdata/boot/rootfs/rootfs-next.erofs", "/sysdata/boot/rootfs/rootfs-next.hash"}] = true
	var m Media
	root, err := SelectRoot(Config{RootHash: goodHash}, &m, f.ops())
	if err != nil {
		t.Fatal(err)
	}
	if f.backing(root.Data) != "/sysdata/boot/rootfs/rootfs-next.erofs" || root.Mapper != RootMapper || !root.FromSlot {
		t.Errorf("selected %+v (%s)", root, f.backing(root.Data))
	}
	if !strings.HasPrefix(root.Source, "/dev/mapper/") {
		t.Error("a locked device must boot through the verity mapping")
	}
}

func TestLockedDeviceNeverBootsAnUnmatchedRoot(t *testing.T) {
	f := installed()
	f.erofs["/sysdata/boot/rootfs/rootfs-active.erofs"] = true
	var m Media
	if root, err := SelectRoot(Config{RootHash: goodHash, Attempts: 3}, &m, f.ops()); err == nil {
		t.Fatalf("booted %+v without a matching hash", root)
	}
	if f.sleeps != 3 {
		t.Errorf("waited %d times, want 3", f.sleeps)
	}
	if _, err := SelectRoot(Config{RootHash: "bad"}, &m, f.ops()); err == nil {
		t.Error("an invalid root hash must not boot")
	}
}

func TestUnlockedUsesTheSignedSlotRaw(t *testing.T) {
	f := installed()
	f.match[[2]string{"/sysdata/boot/rootfs/rootfs-next.erofs", "/sysdata/boot/rootfs/rootfs-next.hash"}] = true
	f.erofs["/sysdata/boot/rootfs/rootfs-active.erofs"] = true
	var m Media
	root, err := SelectRoot(Config{RootHash: goodHash, Unlocked: true}, &m, f.ops())
	if err != nil {
		t.Fatal(err)
	}
	if f.backing(root.Source) != "/sysdata/boot/rootfs/rootfs-next.erofs" || root.Mapper != "" {
		t.Errorf("unlocked root %+v", root)
	}
	if len(f.mapped) != 0 {
		t.Error("the selection mapping must be closed before the raw root is used")
	}
}

func TestUnlockedFallsBackToAnyRoot(t *testing.T) {
	f := installed()
	f.erofs["/sysdata/boot/rootfs/rootfs-active.erofs"] = true
	var m Media
	root, err := SelectRoot(Config{RootHash: goodHash, Unlocked: true}, &m, f.ops())
	if err != nil || f.backing(root.Source) != "/sysdata/boot/rootfs/rootfs-active.erofs" {
		t.Fatalf("root %+v err %v", root, err)
	}
}

func liveDisks() *fakeDisk {
	f := newFake()
	f.parts = []Partition{
		{Dev: "/dev/sda1", Disk: "sda"}, {Dev: "/dev/sda2", Disk: "sda", PartName: "sing-portable-root"}, {Dev: "/dev/sda3", Disk: "sda", PartName: "sing-portable-hash"},
		{Dev: "/dev/sdb2", Disk: "sdb"}, {Dev: "/dev/sdb3", Disk: "sdb"},
	}
	f.erofs["/dev/sda2"], f.erofs["/dev/sdb2"] = true, true
	f.hashes["/dev/sda3"], f.hashes["/dev/sdb3"] = true, true
	return f
}

func TestLiveNeverPairsAcrossDisks(t *testing.T) {
	f := liveDisks()
	f.match[[2]string{"/dev/sda2", "/dev/sdb3"}] = true
	var m Media
	if root, err := SelectRoot(Config{RootHash: goodHash, Live: true, Attempts: 2}, &m, f.ops()); err == nil {
		t.Fatalf("paired across disks: %+v", root)
	}
	f.match[[2]string{"/dev/sdb2", "/dev/sdb3"}] = true
	root, err := SelectRoot(Config{RootHash: goodHash, Live: true}, &m, f.ops())
	if err != nil || root.Data != "/dev/sdb2" || root.Hash != "/dev/sdb3" {
		t.Fatalf("root %+v err %v", root, err)
	}
}

func TestPortableOnlyUsesItsNamedPartitions(t *testing.T) {
	f := liveDisks()
	f.match[[2]string{"/dev/sdb2", "/dev/sdb3"}] = true
	cfg := Config{RootHash: goodHash, Portable: true, PortableRoot: "sing-portable-root", PortableHash: "sing-portable-hash", Attempts: 2}
	var m Media
	if root, err := SelectRoot(cfg, &m, f.ops()); err == nil {
		t.Fatalf("portable booted an unnamed partition: %+v", root)
	}
	f.match[[2]string{"/dev/sda2", "/dev/sda3"}] = true
	root, err := SelectRoot(cfg, &m, f.ops())
	if err != nil || root.Data != "/dev/sda2" {
		t.Fatalf("root %+v err %v", root, err)
	}
}

func TestOpticalRootPairsOnlyItsOwnFiles(t *testing.T) {
	f := newFake()
	f.parts = []Partition{{Dev: "/dev/sr0", Disk: "sr0"}}
	f.files["/dev/sr0:iso"] = true
	f.isoFiles = true
	f.match[[2]string{"/isomedia/live/rootfs.erofs", "/isomedia/live/rootfs.hash"}] = true
	var m Media
	root, err := SelectRoot(Config{RootHash: goodHash, Live: true}, &m, f.ops())
	if err != nil || !root.Optical || root.FromSlot {
		t.Fatalf("root %+v err %v", root, err)
	}
}

func TestLiveRootReleasesAnUnrelatedInstall(t *testing.T) {
	f := installed()
	f.parts = append(f.parts, Partition{Dev: "/dev/sdb2", Disk: "sdb"}, Partition{Dev: "/dev/sdb3", Disk: "sdb"})
	f.erofs["/dev/sdb2"] = true
	f.hashes["/dev/sdb3"] = true
	f.match[[2]string{"/dev/sdb2", "/dev/sdb3"}] = true
	var m Media
	root, err := SelectRoot(Config{RootHash: goodHash, Live: true}, &m, f.ops())
	if err != nil || root.FromSlot {
		t.Fatalf("root %+v err %v", root, err)
	}
	held, err := ReleaseUnrelatedData(Config{Live: true}, &m, root, f.ops())
	if err != nil || held || m.DataDev != "" || len(f.attached) != 0 {
		t.Fatalf("held=%v err=%v media=%+v loops=%v", held, err, m, f.attached)
	}
	f2 := installed()
	f2.files["/sysdata/.atom-var"] = true
	m2 := Media{DataDev: "/dev/nvme0n1p2"}
	if held, _ := ReleaseUnrelatedData(Config{Portable: true}, &m2, &Root{Data: "/dev/sda2"}, f2.ops()); !held {
		t.Error("a portable root keeps the installed data partition")
	}
	f3 := installed()
	f3.unmount = errors.New("busy")
	m3 := Media{DataDev: "/dev/nvme0n1p2"}
	if _, err := ReleaseUnrelatedData(Config{Live: true}, &m3, &Root{Data: "/dev/sdb2"}, f3.ops()); err == nil {
		t.Error("a data partition that cannot be released must stop the boot")
	}
}

func TestLinkStandardDevices(t *testing.T) {
	dev := t.TempDir()
	if err := os.Symlink("/elsewhere", filepath.Join(dev, "stdin")); err != nil {
		t.Fatal(err)
	}
	LinkStandardDevices(dev)
	want := map[string]string{"fd": "/proc/self/fd", "stdin": "/elsewhere", "stdout": "/proc/self/fd/1", "stderr": "/proc/self/fd/2"}
	for name, target := range want {
		got, err := os.Readlink(filepath.Join(dev, name))
		if err != nil || got != target {
			t.Errorf("%s -> %q (%v), want %q", name, got, err, target)
		}
	}
}
