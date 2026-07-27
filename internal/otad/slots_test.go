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
	// active + next present for every artifact: an image is only promotable together
	// with the signature/hash tree that makes it bootable.
	os.WriteFile(filepath.Join(esp, "kernelcache-active.efi"), []byte("kc-active"), 0o644)
	os.WriteFile(filepath.Join(esp, "kernelcache-next.efi"), []byte("kc-next"), 0o644)
	os.WriteFile(filepath.Join(esp, "kernelcache-active.efi.sig"), []byte("sig-active"), 0o644)
	os.WriteFile(filepath.Join(esp, "kernelcache-next.efi.sig"), []byte("sig-next"), 0o644)
	os.WriteFile(filepath.Join(rfs, "rootfs-active.erofs"), []byte("rfs-active"), 0o644)
	os.WriteFile(filepath.Join(rfs, "rootfs-next.erofs"), []byte("rfs-next"), 0o644)
	os.WriteFile(filepath.Join(rfs, "rootfs-active.hash"), []byte("hash-active"), 0o644)
	os.WriteFile(filepath.Join(rfs, "rootfs-next.hash"), []byte("hash-next"), 0o644)

	if err := PromoteSlots(dirs); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(rfs, "rootfs-active.hash")); string(b) != "hash-next" {
		t.Errorf("rootfs active hash = %q, want hash-next", b)
	}
	if b, _ := os.ReadFile(filepath.Join(esp, "kernelcache-active.efi.sig")); string(b) != "sig-next" {
		t.Errorf("kc active sig = %q, want sig-next", b)
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

// A rootfs image staged without its verity hash tree must NOT be promoted: the new
// image against the old hash tree fails dm-verity, and the device powers off instead
// of booting. Refuse the whole group and leave the running slot untouched.
func TestPromoteRefusesPartialGroup(t *testing.T) {
	rfs := t.TempDir()
	dirs := StageDirs{Rootfs: rfs}
	os.WriteFile(filepath.Join(rfs, "rootfs-active.erofs"), []byte("rfs-active"), 0o644)
	os.WriteFile(filepath.Join(rfs, "rootfs-active.hash"), []byte("hash-active"), 0o644)
	os.WriteFile(filepath.Join(rfs, "rootfs-next.erofs"), []byte("rfs-next"), 0o644)

	if err := PromoteSlots(dirs); err == nil {
		t.Fatal("promote accepted a rootfs with no staged hash tree")
	}
	if b, _ := os.ReadFile(filepath.Join(rfs, "rootfs-active.erofs")); string(b) != "rfs-active" {
		t.Errorf("active rootfs was mutated by a refused promote: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(rfs, "rootfs-active.hash")); string(b) != "hash-active" {
		t.Errorf("active hash was mutated by a refused promote: %q", b)
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
