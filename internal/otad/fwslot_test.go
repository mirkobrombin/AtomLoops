package otad

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeFile is a tiny helper for slot tests.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestActivateAndRollbackFirmwareSlot(t *testing.T) {
	dir := t.TempDir()

	// An existing active firmware image + its anchor (the currently running one).
	writeFile(t, filepath.Join(dir, "firmware-active.img"), "OLD-IMG")
	writeFile(t, filepath.Join(dir, "firmware-active.hash"), "OLD-HASH")
	oldM, oldMS, oldC, oldCS, oldRoot := signedAnchor(t, true)
	if err := WriteFirmwareAnchor(dir, "active", oldM, oldMS, oldC, oldCS); err != nil {
		t.Fatal(err)
	}

	// A staged candidate as -next.
	writeFile(t, filepath.Join(dir, "firmware-next.img"), "NEW-IMG")
	writeFile(t, filepath.Join(dir, "firmware-next.hash"), "NEW-HASH")
	newM, newMS, newC, newCS, newRoot := signedAnchor(t, true)
	if err := WriteFirmwareAnchor(dir, "next", newM, newMS, newC, newCS); err != nil {
		t.Fatal(err)
	}

	if err := ActivateFirmwareSlot(dir); err != nil {
		t.Fatalf("activate: %v", err)
	}

	// The active image is now the new one; the old is preserved as .bak.
	if b, _ := os.ReadFile(filepath.Join(dir, "firmware-active.img")); string(b) != "NEW-IMG" {
		t.Errorf("active image = %q, want NEW-IMG", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "firmware-active.img.bak")); string(b) != "OLD-IMG" {
		t.Errorf("backup image = %q, want OLD-IMG", b)
	}
	// The active anchor verifies with the new root, not the old.
	if _, _, err := VerifyFirmwareAnchor(dir, "active", newRoot, time.Now(), "default"); err != nil {
		t.Fatalf("active anchor should verify with new root: %v", err)
	}
	if _, _, err := VerifyFirmwareAnchor(dir, "active", oldRoot, time.Now(), "default"); err == nil {
		t.Fatal("active anchor must not verify with old root after activation")
	}

	// Rollback restores the old image and anchor together.
	if err := RollbackFirmwareSlot(dir); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "firmware-active.img")); string(b) != "OLD-IMG" {
		t.Errorf("after rollback active image = %q, want OLD-IMG", b)
	}
	if _, _, err := VerifyFirmwareAnchor(dir, "active", oldRoot, time.Now(), "default"); err != nil {
		t.Fatalf("after rollback active anchor should verify with old root: %v", err)
	}
}

func TestActivateFirmwareSlotMissingNextIsError(t *testing.T) {
	if err := ActivateFirmwareSlot(t.TempDir()); err == nil {
		t.Fatal("activation with no staged -next must error, not silently succeed")
	}
}

func TestImagePath(t *testing.T) {
	cases := map[string]string{
		"firmware.img":  "/d/firmware-next.img",
		"firmware.hash": "/d/firmware-next.hash",
	}
	for name, want := range cases {
		if got := imagePath("/d", "next", name); got != want {
			t.Errorf("imagePath(/d,next,%q) = %q, want %q", name, got, want)
		}
	}
}
