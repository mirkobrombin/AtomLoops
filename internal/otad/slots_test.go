package otad

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

func TestBootStateRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "boot-state")
	in := BootState{Target: "next", Trial: true, Attempts: 3}
	if err := WriteBootState(p, in); err != nil {
		t.Fatal(err)
	}
	if got := in.Marshal(); got != "target=next\ntrial=1\nattempts=3\n" {
		t.Fatalf("marshal = %q", got)
	}
	out, err := ReadBootState(p)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("roundtrip: got %+v want %+v", out, in)
	}
}

func TestPromoteSlots(t *testing.T) {
	esp := t.TempDir()
	rfs := t.TempDir()
	dirs := StageDirs{Rootfs: rfs, ESP: esp}
	// active + next present for both artifacts
	os.WriteFile(filepath.Join(esp, "kernelcache-active.efi"), []byte("kc-active"), 0o644)
	os.WriteFile(filepath.Join(esp, "kernelcache-next.efi"), []byte("kc-next"), 0o644)
	os.WriteFile(filepath.Join(rfs, "rootfs-active.erofs"), []byte("rfs-active"), 0o644)
	os.WriteFile(filepath.Join(rfs, "rootfs-next.erofs"), []byte("rfs-next"), 0o644)

	if err := PromoteSlots(dirs); err != nil {
		t.Fatal(err)
	}
	// next -> active, old active -> prev
	if b, _ := os.ReadFile(filepath.Join(esp, "kernelcache-active.efi")); string(b) != "kc-next" {
		t.Errorf("kc active = %q, want kc-next", b)
	}
	if b, _ := os.ReadFile(filepath.Join(esp, "kernelcache-prev.efi")); string(b) != "kc-active" {
		t.Errorf("kc prev = %q, want kc-active", b)
	}
	if _, err := os.Stat(filepath.Join(esp, "kernelcache-next.efi")); !os.IsNotExist(err) {
		t.Errorf("kc-next should be gone after promote")
	}
	if b, _ := os.ReadFile(filepath.Join(rfs, "rootfs-active.erofs")); string(b) != "rfs-next" {
		t.Errorf("rootfs active = %q, want rfs-next", b)
	}
}

func TestSyncBootStateFromWAL(t *testing.T) {
	esp := t.TempDir()
	wal := filepath.Join(t.TempDir(), "deployment.json")
	d := deployment.New("dev", "v1")
	d.Deploy("v2") // pending candidate
	d.Save(wal)
	dirs := StageDirs{ESP: esp}

	if err := SyncBootState(wal, dirs); err != nil {
		t.Fatal(err)
	}
	bs, _ := ReadBootState(filepath.Join(esp, "boot-state"))
	if bs.Target != "next" || !bs.Trial {
		t.Fatalf("pending WAL should arm next: %+v", bs)
	}
	// no ESP -> no-op, no panic
	if err := SyncBootState(wal, StageDirs{}); err != nil {
		t.Fatal(err)
	}
}
