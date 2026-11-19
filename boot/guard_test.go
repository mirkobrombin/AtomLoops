package boot

import (
	"errors"
	"testing"
)

func phone() *fakeDisk {
	f := newFake()
	f.parts = []Partition{
		{Dev: "/dev/sda30", Disk: "sda", PartName: "persist"},
		{Dev: "/dev/sda31", Disk: "sda", PartName: "userdata"},
		{Dev: "/dev/sdb1", Disk: "sdb", PartName: "efs"},
	}
	f.files["/dev/sda30:data"] = true
	f.files["/dev/sda31:data"] = true
	f.files["/sysdata/boot/rootfs/rootfs-active.erofs"] = true
	f.files["/sysdata/boot/rootfs/rootfs-active.hash"] = true
	f.match[[2]string{"/sysdata/boot/rootfs/rootfs-active.erofs", "/sysdata/boot/rootfs/rootfs-active.hash"}] = true
	return f
}

func TestDataPartIsTheOnlyCandidateOnceTheGuardSettles(t *testing.T) {
	f := phone()
	ops := f.ops()
	guards := 0
	ops.Guard = func(keep string) (int, error) {
		guards++
		if keep != "userdata" {
			t.Fatalf("guard keeps %q", keep)
		}
		return 3, nil
	}
	var m Media
	root, err := SelectRoot(Config{RootHash: goodHash, DataPart: "userdata"}, &m, ops)
	if err != nil {
		t.Fatal(err)
	}
	if m.DataDev != "/dev/sda31" || root == nil {
		t.Fatalf("data %s", m.DataDev)
	}
	if guards < guardSettle+1 {
		t.Fatalf("mounted after %d guard scans", guards)
	}
}

func TestNoDataIsMountedWhileTheGuardFails(t *testing.T) {
	f := phone()
	ops := f.ops()
	ops.Guard = func(string) (int, error) { return 0, errors.New("sdb stays writable") }
	var m Media
	if _, err := SelectRoot(Config{RootHash: goodHash, DataPart: "userdata", Attempts: 10}, &m, ops); err == nil {
		t.Fatal("a root was found with a writable disk left")
	}
	if m.DataDev != "" {
		t.Fatalf("mounted %s with the guard failing", m.DataDev)
	}
}

func TestGuardRestartsWhenNewDisksAppear(t *testing.T) {
	f := phone()
	ops := f.ops()
	seen := []int{1, 2, 2, 3, 3, 3, 3}
	i := 0
	ops.Guard = func(string) (int, error) {
		n := seen[min(i, len(seen)-1)]
		i++
		return n, nil
	}
	var m Media
	if _, err := SelectRoot(Config{RootHash: goodHash, DataPart: "userdata"}, &m, ops); err != nil {
		t.Fatal(err)
	}
	if i != 7 {
		t.Fatalf("mounted after %d scans, before the device list settled", i)
	}
}
