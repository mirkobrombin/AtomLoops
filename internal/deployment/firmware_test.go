package deployment

import "testing"

const fwB = "wifi" // a bundle name for the firmware track tests

func TestFirmwareDeployProbePromote(t *testing.T) {
	d := New("dev", "v1")
	if !d.DeployFirmware(fwB, 1, "hash-1") {
		t.Fatal("DeployFirmware(1) refused on a fresh device")
	}
	if !d.HasPendingFirmware(fwB) {
		t.Fatal("firmware candidate should be pending after deploy")
	}
	if d.RecordFirmwareProbe(fwB) || d.RecordFirmwareProbe(fwB) {
		t.Fatal("promotion happened before stable_threshold probes")
	}
	if !d.RecordFirmwareProbe(fwB) {
		t.Fatal("third clean probe should promote at threshold 3")
	}
	b := d.Firmware.Bundle(fwB)
	if b.CurrentVersion != 1 || b.LastKnownGood != 1 {
		t.Fatalf("after promote current/lkg = %d/%d, want 1/1", b.CurrentVersion, b.LastKnownGood)
	}
	if b.MinVersion != 1 {
		t.Fatalf("anti-rollback floor = %d, want 1 (advanced only on promote)", b.MinVersion)
	}
	if d.HasPendingFirmware(fwB) || b.State != KCStable {
		t.Fatal("firmware track should be stable with no pending after promote")
	}
}

func TestFirmwareAntiRollbackRefusesDowngrade(t *testing.T) {
	d := New("dev", "v1")
	d.DeployFirmware(fwB, 2, "hash-2")
	for i := 0; i < 3; i++ {
		d.RecordFirmwareProbe(fwB)
	}
	if d.Firmware.Bundle(fwB).MinVersion != 2 {
		t.Fatalf("floor = %d, want 2", d.Firmware.Bundle(fwB).MinVersion)
	}
	if d.DeployFirmware(fwB, 1, "old") {
		t.Fatal("a version below the floor must be refused")
	}
	if d.DeployFirmware(fwB, 2, "same") {
		t.Fatal("a version equal to the floor must be refused")
	}
	if !d.DeployFirmware(fwB, 3, "hash-3") {
		t.Fatal("a version above the floor must be accepted")
	}
}

func TestFirmwareRollbackDoesNotAdvance(t *testing.T) {
	d := New("dev", "v1")
	d.DeployFirmware(fwB, 1, "h1")
	for i := 0; i < 3; i++ {
		d.RecordFirmwareProbe(fwB)
	}
	// Stage a second candidate, probe once (switches current), then roll back.
	d.DeployFirmware(fwB, 2, "h2")
	d.RecordFirmwareProbe(fwB)
	if d.Firmware.Bundle(fwB).CurrentVersion != 2 {
		t.Fatalf("current after first probe = %d, want 2", d.Firmware.Bundle(fwB).CurrentVersion)
	}
	d.RollbackFirmware(fwB)
	b := d.Firmware.Bundle(fwB)
	if b.CurrentVersion != 1 {
		t.Fatalf("after rollback current = %d, want the last known good 1", b.CurrentVersion)
	}
	if d.HasPendingFirmware(fwB) || b.State != KCStable {
		t.Fatal("rollback should clear the pending candidate and return to stable")
	}
	if b.MinVersion != 1 {
		t.Fatalf("a rolled-back candidate must not advance the floor, got %d", b.MinVersion)
	}
}

func TestFirmwareBundlesAreIndependent(t *testing.T) {
	d := New("dev", "v1")
	d.DeployFirmware("wifi", 1, "w1")
	d.DeployFirmware("gpu", 1, "g1")
	// Promote wifi to stability; gpu fails its probe and rolls back -- independently.
	for i := 0; i < 3; i++ {
		d.RecordFirmwareProbe("wifi")
	}
	d.RollbackFirmware("gpu")
	if w := d.Firmware.Bundle("wifi"); w.CurrentVersion != 1 || w.MinVersion != 1 {
		t.Fatalf("wifi should be promoted independently: %+v", w)
	}
	if d.HasPendingFirmware("gpu") || d.Firmware.Bundle("gpu").MinVersion != 0 {
		t.Fatal("gpu rollback must not advance its own floor and must clear its candidate")
	}
	if d.HasPendingFirmware("wifi") {
		t.Fatal("wifi should have no candidate after promotion")
	}
}

func TestFirmwareTrackIsIndependentOfRootfs(t *testing.T) {
	d := New("dev", "v1")
	rootfsBefore := d.RootFS
	kcBefore := d.Kernelcache

	d.DeployFirmware(fwB, 1, "h1")
	d.RecordFirmwareProbe(fwB)
	if d.RootFS != rootfsBefore || d.Kernelcache != kcBefore {
		t.Fatal("a firmware transition must not touch the rootfs or kernelcache tracks")
	}

	fwBefore := *d.Firmware.Bundle(fwB)
	d.Deploy("v2")
	if *d.Firmware.Bundle(fwB) != fwBefore {
		t.Fatal("a rootfs deploy must not touch the firmware track")
	}
}
