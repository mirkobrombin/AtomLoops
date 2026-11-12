package live

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleMountinfo = `1 0 0:1 / / rw - rootfs rootfs rw
22 1 253:0 / / ro,relatime shared:1 - erofs /dev/mapper/vroot ro
23 22 0:5 / /dev rw,nosuid shared:2 - devtmpfs devtmpfs rw
24 22 0:20 / /proc rw - proc proc rw
25 22 259:3 / /var rw,relatime shared:3 - f2fs /dev/nvme0n1p3 rw
26 22 0:30 / /etc rw - overlay overlay rw,lowerdir=/sysroot/etc,upperdir=/sysroot/var/etc-upper,workdir=/sysroot/var/etc-work
27 26 259:3 /etc-resolv /etc/resolv.conf rw - f2fs /dev/nvme0n1p3 rw
28 22 259:3 /home /home rw - f2fs /dev/nvme0n1p3 rw
29 25 0:40 / /var/lib/with\040space rw - tmpfs tmpfs rw
`

func TestReadMounts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mountinfo")
	os.WriteFile(p, []byte(sampleMountinfo), 0o644)
	ms, err := readMounts(p)
	if err != nil {
		t.Fatal(err)
	}
	root, ok := topAt(ms, "/", -1)
	if !ok || root.id != 22 || root.fstype != "erofs" || !root.shared || root.dev != "253:0" {
		t.Fatalf("root %+v", root)
	}
	var points []string
	for _, m := range childrenOf(ms, root.id) {
		points = append(points, m.point)
	}
	if strings.Join(points, " ") != "/dev /proc /var /etc /home" {
		t.Fatalf("children %v", points)
	}
	etc, ok := topAt(ms, "/etc", root.id)
	if !ok || superOption(etc.super, "workdir") != "/sysroot/var/etc-work" {
		t.Fatalf("etc %+v", etc)
	}
	if kids := childrenOf(ms, etc.id); len(kids) != 1 || kids[0].point != "/etc/resolv.conf" {
		t.Fatalf("etc children %+v", kids)
	}
	if _, ok := topAt(ms, "/var/lib/with space", 25); !ok {
		t.Fatal("escaped mount point not decoded")
	}
}

func TestPCRExtendCommand(t *testing.T) {
	var d [32]byte
	for i := range d {
		d[i] = byte(i)
	}
	got := hex.EncodeToString(pcrExtendCommand(15, d))
	want := "800200000041" + "00000182" + "0000000f" + "00000009" + "40000009" + "0000" + "00" + "0000" +
		"00000001" + "000b" + hex.EncodeToString(d[:])
	if got != want {
		t.Fatalf("command\n got %s\nwant %s", got, want)
	}
	if Measurement("a", "v1", "h1", "v2", "h2") == Measurement("a", "v1", "h1", "v2", "h3") {
		t.Fatal("measurement ignores the new root")
	}
}

func TestRunHooks(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	dir := t.TempDir()
	log := filepath.Join(t.TempDir(), "log")
	os.WriteFile(filepath.Join(dir, "10-first"), []byte("#!/bin/sh\necho \"10 $1 $ATOM_APPLY_CLASS $ATOM_FROM $ATOM_TO $ATOM_OLD_ROOT\" >> "+log+"\n"), 0o755)
	os.WriteFile(filepath.Join(dir, "20-second"), []byte("#!/bin/sh\n[ \"$1\" = health ] && exit 3\necho 20 $1 >> "+log+"\n"), 0o755)
	os.WriteFile(filepath.Join(dir, "30-notexec"), []byte("#!/bin/sh\necho never >> "+log+"\n"), 0o644)
	env := Env{Class: "reload", From: "v1", To: "v2", OldRoot: "/old"}
	if err := RunHooks(dir, "switched", env); err != nil {
		t.Fatal(err)
	}
	if err := RunHooks(dir, "health", env); err == nil {
		t.Fatal("a failing health hook passed")
	}
	if err := RunHooks(filepath.Join(dir, "missing"), "switched", env); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(log)
	if string(b) != "10 switched reload v1 v2 /old\n20 switched\n10 health reload v1 v2 /old\n" {
		t.Fatalf("log %q", b)
	}
}
