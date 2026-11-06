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
	// The ESP keeps next until the caller commits boot-state and WAL.
	if b, _ := os.ReadFile(filepath.Join(esp, "kernelcache-active.efi")); string(b) != "kc-next" {
		t.Errorf("kc active = %q, want kc-next", b)
	}
	if b, _ := os.ReadFile(filepath.Join(esp, "kernelcache-prev.efi")); string(b) != "kc-active" {
		t.Errorf("kc prev = %q, want kc-active", b)
	}
	if b, _ := os.ReadFile(filepath.Join(esp, "kernelcache-next.efi")); string(b) != "kc-next" {
		t.Errorf("kc next = %q, want kc-next", b)
	}
	if b, _ := os.ReadFile(filepath.Join(rfs, "rootfs-active.erofs")); string(b) != "rfs-next" {
		t.Errorf("rootfs active = %q, want rfs-next", b)
	}
	if b, _ := os.ReadFile(filepath.Join(rfs, "rootfs-next.erofs")); string(b) != "rfs-next" {
		t.Errorf("rootfs next = %q, want rfs-next", b)
	}
	if err := PromoteSlots(dirs); err != nil {
		t.Fatalf("idempotent promote retry: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(rfs, "rootfs-prev.erofs")); string(b) != "rfs-active" {
		t.Errorf("rootfs prev changed on retry: %q", b)
	}
	CleanupNextSlots(dirs)
	if _, err := os.Stat(filepath.Join(esp, "kernelcache-next.efi")); !os.IsNotExist(err) {
		t.Errorf("kc-next should be gone after cleanup")
	}
	if _, err := os.Stat(filepath.Join(rfs, "rootfs-next.erofs")); !os.IsNotExist(err) {
		t.Errorf("rootfs-next should be gone after cleanup")
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

func TestPromotePreflightsEveryGroup(t *testing.T) {
	esp := t.TempDir()
	rfs := t.TempDir()
	dirs := StageDirs{Rootfs: rfs, ESP: esp}
	os.WriteFile(filepath.Join(esp, "kernelcache-active.efi"), []byte("kc-active"), 0o644)
	os.WriteFile(filepath.Join(esp, "kernelcache-next.efi"), []byte("kc-next"), 0o644)
	os.WriteFile(filepath.Join(esp, "kernelcache-active.efi.sig"), []byte("sig-active"), 0o644)
	os.WriteFile(filepath.Join(esp, "kernelcache-next.efi.sig"), []byte("sig-next"), 0o644)
	os.WriteFile(filepath.Join(rfs, "rootfs-active.erofs"), []byte("rfs-active"), 0o644)
	os.WriteFile(filepath.Join(rfs, "rootfs-active.hash"), []byte("hash-active"), 0o644)
	os.WriteFile(filepath.Join(rfs, "rootfs-next.erofs"), []byte("rfs-next"), 0o644)

	if err := PromoteSlots(dirs); err == nil {
		t.Fatal("promote accepted an incomplete rootfs group")
	}
	if b, _ := os.ReadFile(filepath.Join(esp, "kernelcache-active.efi")); string(b) != "kc-active" {
		t.Errorf("ESP was mutated before every group passed preflight: %q", b)
	}
}

func TestPromoteRejectsEmptySlot(t *testing.T) {
	esp := t.TempDir()
	os.WriteFile(filepath.Join(esp, "kernelcache-active.efi"), []byte("kc-active"), 0o644)
	os.WriteFile(filepath.Join(esp, "kernelcache-next.efi"), nil, 0o644)
	os.WriteFile(filepath.Join(esp, "kernelcache-active.efi.sig"), []byte("sig-active"), 0o644)
	os.WriteFile(filepath.Join(esp, "kernelcache-next.efi.sig"), []byte("sig-next"), 0o644)

	if err := PromoteSlots(StageDirs{ESP: esp}); err == nil {
		t.Fatal("promote accepted an empty kernelcache")
	}
	if b, _ := os.ReadFile(filepath.Join(esp, "kernelcache-active.efi")); string(b) != "kc-active" {
		t.Errorf("active kernelcache was mutated: %q", b)
	}
}

func TestPromoteRejectsMissingCandidateWithPreviousSlot(t *testing.T) {
	rfs := t.TempDir()
	for _, slot := range []string{"active", "prev"} {
		os.WriteFile(filepath.Join(rfs, "rootfs-"+slot+".erofs"), []byte(slot+"-image"), 0o644)
		os.WriteFile(filepath.Join(rfs, "rootfs-"+slot+".hash"), []byte(slot+"-hash"), 0o644)
	}

	if err := PromoteSlots(StageDirs{Rootfs: rfs}); err == nil {
		t.Fatal("promote accepted a missing candidate because a previous slot existed")
	}
	if b, _ := os.ReadFile(filepath.Join(rfs, "rootfs-active.erofs")); string(b) != "active-image" {
		t.Errorf("active rootfs was mutated: %q", b)
	}
}

func TestPromoteRejectsCandidateWithoutActiveSlot(t *testing.T) {
	rfs := t.TempDir()
	for _, slot := range []string{"prev", "next"} {
		os.WriteFile(filepath.Join(rfs, "rootfs-"+slot+".erofs"), []byte(slot+"-image"), 0o644)
		os.WriteFile(filepath.Join(rfs, "rootfs-"+slot+".hash"), []byte(slot+"-hash"), 0o644)
	}

	if err := PromoteSlots(StageDirs{Rootfs: rfs}); err == nil {
		t.Fatal("promote accepted a candidate with no active slot")
	}
	if b, _ := os.ReadFile(filepath.Join(rfs, "rootfs-prev.erofs")); string(b) != "prev-image" {
		t.Errorf("previous rootfs was mutated: %q", b)
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

func TestPromoteSlotsSurvivesAPowerCutAtEveryStep(t *testing.T) {
	real := promoteStep
	defer func() { promoteStep = real }()
	sets := []struct{ dir, prefix, a, b string }{
		{"rfs", "rootfs", ".erofs", ".hash"},
		{"esp", "kernelcache", ".efi", ".efi.sig"},
	}
	for cut := 0; ; cut++ {
		root := t.TempDir()
		dirs := StageDirs{Rootfs: filepath.Join(root, "rfs"), ESP: filepath.Join(root, "esp")}
		for _, st := range sets {
			d := filepath.Join(root, st.dir)
			os.MkdirAll(d, 0o755)
			for _, v := range []string{"prev", "active", "next"} {
				os.WriteFile(filepath.Join(d, st.prefix+"-"+v+st.a), []byte("v-"+v), 0o644)
				os.WriteFile(filepath.Join(d, st.prefix+"-"+v+st.b), []byte("v-"+v), 0o644)
			}
		}
		steps := 0
		promoteStep = func(copyFile bool, src, dst string) error {
			if steps == cut {
				return os.ErrDeadlineExceeded
			}
			steps++
			return real(copyFile, src, dst)
		}
		err := PromoteSlots(dirs)
		for _, st := range sets {
			d := filepath.Join(root, st.dir)
			for _, want := range []string{"v-active", "v-next"} {
				found := false
				for _, v := range []string{"prev", "active", "next"} {
					x, _ := os.ReadFile(filepath.Join(d, st.prefix+"-"+v+st.a))
					y, _ := os.ReadFile(filepath.Join(d, st.prefix+"-"+v+st.b))
					found = found || (string(x) == want && string(y) == want)
				}
				if !found {
					t.Fatalf("cut after %d steps: no complete %s set for %s", cut, st.prefix, want)
				}
			}
		}
		if err == nil {
			if cut < 8 {
				t.Fatalf("promotion finished in %d steps, want 8", cut)
			}
			return
		}
	}
}
