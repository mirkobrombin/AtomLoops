package boot

import "testing"

func TestDiagnose(t *testing.T) {
	disk := []Partition{{Dev: "/dev/nvme0n1p1"}, {Dev: "/dev/nvme0n1p2"}}
	broken := Media{Unmountable: []UnmountablePartition{{Dev: "/dev/nvme0n1p2", FS: "f2fs"}}}
	held := Media{DataDev: "/dev/nvme0n1p2"}
	slots := []string{"/sysdata/boot/rootfs/rootfs-active.erofs"}
	hashes := []string{"/sysdata/boot/rootfs/rootfs-active.hash"}
	for _, c := range []struct {
		name     string
		f        Facts
		code     string
		rollback bool
	}{
		{"no disk", Facts{}, "B01", false},
		{"no sinty partition", Facts{Partitions: disk}, "B01", false},
		{"read errors", Facts{Partitions: disk, Media: broken,
			KernelLog: "blk_update_request: I/O error, dev nvme0n1, sector 1234 op 0x0:(READ)"}, "B02", false},
		{"read errors on another disk", Facts{Partitions: disk, Media: broken,
			KernelLog: "I/O error, dev sda, sector 8"}, "B03", false},
		{"nvme reset", Facts{Partitions: disk, Media: held, SlotFiles: slots, HashFiles: hashes,
			KernelLog: "nvme nvme0: I/O 12 QID 3 timeout"}, "B02", false},
		{"unmountable", Facts{Partitions: disk, Media: broken}, "B03", false},
		{"no image", Facts{Partitions: disk, Media: held}, "B04", false},
		{"slots deleted", Facts{Partitions: disk, Media: Media{Empty: []string{"/dev/nvme0n1p2"}}}, "B04", false},
		{"no hash tree", Facts{Partitions: disk, Media: held, SlotFiles: slots}, "B05", false},
		{"hash mismatch", Facts{Partitions: disk, Media: held, SlotFiles: slots, HashFiles: hashes}, "B06", true},
		{"verification fails", Facts{Partitions: disk, Media: held, SlotFiles: slots, HashFiles: hashes, HashMatch: true}, "B07", true},
	} {
		d := Diagnose(c.f)
		if d.Code != c.code || d.RollbackHelps != c.rollback {
			t.Errorf("%s: %s rollback=%v, want %s rollback=%v", c.name, d.Code, d.RollbackHelps, c.code, c.rollback)
		}
		if d.Cause == "" || d.Action == "" || d.Phase == "" {
			t.Errorf("%s: incomplete %+v", c.name, d)
		}
	}
}

func TestFailingNVMeIsAStorageFault(t *testing.T) {
	smart := make([]byte, 512)
	smart[0] = 0x04
	smart[160] = 7
	h := ParseNVMeSMART("nvme0", smart)
	if !h.Failing() || h.MediaErrors != 7 {
		t.Fatalf("health = %+v", h)
	}
	f := Facts{
		Partitions: []Partition{{Dev: "/dev/nvme0n1p2"}},
		Media:      Media{Unmountable: []UnmountablePartition{{Dev: "/dev/nvme0n1p2", FS: "f2fs"}}},
		Disks:      []DiskHealth{h},
	}
	if d := Diagnose(f); d.Code != "B02" {
		t.Fatalf("diagnosis = %+v", d)
	}
	f.Disks = []DiskHealth{ParseNVMeSMART("nvme1", smart)}
	if d := Diagnose(f); d.Code != "B03" {
		t.Fatalf("a failing disk that does not hold the data: %+v", d)
	}
	f.Disks = []DiskHealth{ParseNVMeSMART("nvme0", make([]byte, 512))}
	if d := Diagnose(f); d.Code != "B03" {
		t.Fatalf("a healthy disk: %+v", d)
	}
}
