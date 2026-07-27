package otad

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

const testBundle = "default"

// firmwareWAL writes a WAL with a pending firmware candidate for testBundle at the
// given stable threshold, and returns its path.
func firmwareWAL(t *testing.T, threshold int) string {
	t.Helper()
	d := deployment.New("dev-1", "v1")
	d.Firmware.Bundle(testBundle).StableThreshold = threshold
	if !d.DeployFirmware(testBundle, 5, "feedface00112233") {
		t.Fatal("DeployFirmware refused")
	}
	p := filepath.Join(t.TempDir(), "deployment.json")
	if err := d.Save(p); err != nil {
		t.Fatal(err)
	}
	return p
}

// firmwareSlotOnDisk lays down an activated firmware slot (new active + old backup)
// in the bundle subdir so rollback and finalize have something to act on.
func firmwareSlotOnDisk(t *testing.T, fwdir string) {
	t.Helper()
	dir := filepath.Join(fwdir, testBundle)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "firmware-active.img"), "NEW-IMG")
	writeFile(t, filepath.Join(dir, "firmware-active.img.bak"), "OLD-IMG")
	writeFile(t, filepath.Join(dir, "firmware-active.hash"), "NEW-HASH")
	writeFile(t, filepath.Join(dir, "firmware-active.hash.bak"), "OLD-HASH")
	m, ms, c, cs, _ := signedAnchor(t, true)
	if err := WriteFirmwareAnchor(dir, "active", m, ms, c, cs); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"fw-manifest-active.json", "fw-manifest-active.json.sig", "fw-signing-cert-active.json", "fw-signing-cert-active.json.sig"} {
		writeFile(t, filepath.Join(dir, f+".bak"), "OLD-ANCHOR")
	}
}

func TestFirmwareBootConfirmRollbackOnBadProbe(t *testing.T) {
	wal := firmwareWAL(t, 2)
	fwdir := t.TempDir()
	firmwareSlotOnDisk(t, fwdir)
	dirs := StageDirs{Firmware: fwdir}

	msg, err := FirmwareBootConfirm(wal, dirs, testBundle, false)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	// The active firmware image is restored from the backup.
	if b, _ := os.ReadFile(filepath.Join(fwdir, testBundle, "firmware-active.img")); string(b) != "OLD-IMG" {
		t.Errorf("after bad probe active img = %q, want OLD-IMG (%s)", b, msg)
	}
	// The WAL no longer has a firmware candidate.
	d, _ := deployment.Load(wal)
	if d.HasPendingFirmware(testBundle) {
		t.Errorf("firmware candidate still pending after rollback: %+v", d.Firmware.Bundle(testBundle))
	}
}

func TestFirmwareBootConfirmPromoteDropsBackups(t *testing.T) {
	wal := firmwareWAL(t, 1) // promotes on the first clean probe
	fwdir := t.TempDir()
	firmwareSlotOnDisk(t, fwdir)
	dirs := StageDirs{Firmware: fwdir}

	msg, err := FirmwareBootConfirm(wal, dirs, testBundle, true)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	// Promotion keeps the new active image and drops the rollback backup.
	if b, _ := os.ReadFile(filepath.Join(fwdir, testBundle, "firmware-active.img")); string(b) != "NEW-IMG" {
		t.Errorf("after promote active img = %q, want NEW-IMG (%s)", b, msg)
	}
	if _, err := os.Stat(filepath.Join(fwdir, testBundle, "firmware-active.img.bak")); !os.IsNotExist(err) {
		t.Errorf("backup image should be gone after promote, stat err = %v", err)
	}
}

func TestFirmwareBootConfirmAllNoCandidate(t *testing.T) {
	d := deployment.New("dev-1", "v1")
	wal := filepath.Join(t.TempDir(), "deployment.json")
	if err := d.Save(wal); err != nil {
		t.Fatal(err)
	}
	msg, err := FirmwareBootConfirmAll(wal, StageDirs{Firmware: t.TempDir()}, true)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if msg != "no firmware candidate in flight" {
		t.Errorf("unexpected message with no candidate: %q", msg)
	}
}
