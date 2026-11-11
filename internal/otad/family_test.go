package otad

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func onBoard(t *testing.T, compatible string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "compatible")
	os.WriteFile(p, []byte(compatible), 0o644)
	old := deviceTreeCompatible
	deviceTreeCompatible = p
	t.Cleanup(func() { deviceTreeCompatible = old })
}

func put(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "<none>"
	}
	return string(b)
}

func TestMachineFamily(t *testing.T) {
	onBoard(t, "nvidia,p3768-0000+p3767-0005\x00nvidia,tegra234\x00")
	if f := MachineFamily(); f != "l4t" {
		t.Fatalf("orin: %q", f)
	}
	onBoard(t, "rockchip,rk3588\x00")
	if f := MachineFamily(); f != "" {
		t.Fatalf("rk3588: %q", f)
	}
	deviceTreeCompatible = filepath.Join(t.TempDir(), "absent")
	if f := MachineFamily(); f != "" {
		t.Fatalf("no device tree: %q", f)
	}
}

func slotsWithMain(t *testing.T) StageDirs {
	esp, rfs := t.TempDir(), t.TempDir()
	put(t, esp, "kernelcache-active.efi", "kc-a")
	put(t, esp, "kernelcache-active.efi.sig", "sig-a")
	put(t, esp, "kernelcache-next.efi", "kc-n")
	put(t, esp, "kernelcache-next.efi.sig", "sig-n")
	put(t, rfs, "rootfs-active.erofs", "r-a")
	put(t, rfs, "rootfs-active.hash", "h-a")
	put(t, rfs, "rootfs-next.erofs", "r-n")
	put(t, rfs, "rootfs-next.hash", "h-n")
	return StageDirs{Rootfs: rfs, ESP: esp}
}

func TestPromoteRotatesFamilyKernels(t *testing.T) {
	dirs := slotsWithMain(t)
	put(t, dirs.ESP, "kernelcache-active.l4t.efi", "l4t-a")
	put(t, dirs.ESP, "kernelcache-active.l4t.efi.sig", "l4t-sig-a")
	put(t, dirs.ESP, "kernelcache-next.l4t.efi", "l4t-n")
	put(t, dirs.ESP, "kernelcache-next.l4t.efi.sig", "l4t-sig-n")
	if err := PromoteSlots(dirs); err != nil {
		t.Fatal(err)
	}
	if read(dirs.ESP, "kernelcache-active.l4t.efi") != "l4t-n" || read(dirs.ESP, "kernelcache-prev.l4t.efi") != "l4t-a" {
		t.Fatalf("active %q prev %q", read(dirs.ESP, "kernelcache-active.l4t.efi"), read(dirs.ESP, "kernelcache-prev.l4t.efi"))
	}
	if read(dirs.ESP, "kernelcache-active.l4t.efi.sig") != "l4t-sig-n" {
		t.Fatal("signature not promoted with its kernel")
	}
	if err := PromoteSlots(dirs); err != nil {
		t.Fatal(err)
	}
	if read(dirs.ESP, "kernelcache-prev.l4t.efi") != "l4t-a" {
		t.Fatal("a retry changed the previous kernel")
	}
	CleanupNextSlots(dirs)
	if read(dirs.ESP, "kernelcache-next.l4t.efi") != "<none>" {
		t.Fatal("next family kernel left after cleanup")
	}
}

func TestPromoteWithoutFamilyKernelRetiresTheOldOne(t *testing.T) {
	dirs := slotsWithMain(t)
	put(t, dirs.ESP, "kernelcache-active.l4t.efi", "l4t-a")
	put(t, dirs.ESP, "kernelcache-active.l4t.efi.sig", "l4t-sig-a")
	put(t, dirs.ESP, "kernelcache-prev.l4t.efi", "l4t-older")
	if err := PromoteSlots(dirs); err != nil {
		t.Fatal(err)
	}
	if read(dirs.ESP, "kernelcache-active.l4t.efi") != "<none>" {
		t.Fatal("a family kernel of the old release stayed active next to the new root")
	}
	if read(dirs.ESP, "kernelcache-prev.l4t.efi") != "l4t-a" {
		t.Fatalf("previous family kernel %q", read(dirs.ESP, "kernelcache-prev.l4t.efi"))
	}
	if err := PromoteSlots(dirs); err != nil {
		t.Fatal(err)
	}
	if read(dirs.ESP, "kernelcache-prev.l4t.efi") != "l4t-a" {
		t.Fatal("a retry dropped the previous family kernel")
	}
}

func TestPromoteFinishesFamiliesAfterACrash(t *testing.T) {
	dirs := slotsWithMain(t)
	put(t, dirs.ESP, "kernelcache-next.l4t.efi", "l4t-n")
	put(t, dirs.ESP, "kernelcache-next.l4t.efi.sig", "l4t-sig-n")
	put(t, dirs.ESP, "kernelcache-active.l4t.efi", "l4t-a")
	put(t, dirs.ESP, "kernelcache-active.l4t.efi.sig", "l4t-sig-a")
	real := promoteStep
	calls := 0
	promoteStep = func(copyFile bool, src, dst string) error {
		if filepath.Ext(filepath.Base(src)) == ".efi" && filepath.Base(src) == "kernelcache-active.l4t.efi" {
			calls++
			return os.ErrDeadlineExceeded
		}
		return real(copyFile, src, dst)
	}
	if err := PromoteSlots(dirs); err == nil {
		t.Fatal("expected the injected failure")
	}
	promoteStep = real
	if err := PromoteSlots(dirs); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || read(dirs.ESP, "kernelcache-active.l4t.efi") != "l4t-n" {
		t.Fatalf("family kernel not promoted on retry: %q", read(dirs.ESP, "kernelcache-active.l4t.efi"))
	}
	if read(dirs.ESP, familiesPending) != "<none>" {
		t.Fatal("marker left behind")
	}
}

func TestPromoteRefusesHalfAFamilyKernel(t *testing.T) {
	dirs := slotsWithMain(t)
	put(t, dirs.ESP, "kernelcache-next.l4t.efi", "l4t-n")
	if err := PromoteSlots(dirs); err == nil {
		t.Fatal("promoted a family kernel without its signature")
	}
}

func familyServer(t *testing.T) Manifest {
	t.Helper()
	kc, sig := []byte("l4t kernelcache"), []byte("l4t signature")
	mux := http.NewServeMux()
	mux.HandleFunc("/l4t", func(w http.ResponseWriter, r *http.Request) { w.Write(kc) })
	mux.HandleFunc("/l4t.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(sig) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return Manifest{KernelFamilies: []KernelFamily{{Name: "l4t", URL: srv.URL + "/l4t", Hash: sha256hex(kc), SigURL: srv.URL + "/l4t.sig", SigHash: sha256hex(sig)}}}
}

func TestStageFetchesOnlyThisBoardsKernel(t *testing.T) {
	m := familyServer(t)
	esp := t.TempDir()
	put(t, esp, "kernelcache-next.l4t.efi", "stale")
	onBoard(t, "rockchip,rk3588\x00")
	if err := stageFamily(context.Background(), m, esp); err != nil {
		t.Fatal(err)
	}
	if read(esp, "kernelcache-next.l4t.efi") != "<none>" {
		t.Fatal("an RK3588 fetched or kept the Orin kernel")
	}
	onBoard(t, "nvidia,tegra234\x00")
	if err := stageFamily(context.Background(), m, esp); err != nil {
		t.Fatal(err)
	}
	if read(esp, "kernelcache-next.l4t.efi") != "l4t kernelcache" || read(esp, "kernelcache-next.l4t.efi.sig") != "l4t signature" {
		t.Fatal("Orin kernel not staged")
	}
	m.KernelFamilies[0].Hash = sha256hex([]byte("something else"))
	if err := stageFamily(context.Background(), m, esp); err == nil {
		t.Fatal("a kernel with the wrong hash was staged")
	}
	if read(esp, "kernelcache-next.l4t.efi") != "<none>" {
		t.Fatal("the bad kernel was left on the ESP")
	}
}

func TestPromoteSkipsFamiliesAlreadyDone(t *testing.T) {
	esp := t.TempDir()
	put(t, esp, "kernelcache-prev.l4t.efi", "l4t-a")
	put(t, esp, "kernelcache-prev.l4t.efi.sig", "l4t-sig-a")
	put(t, esp, familiesPending, "l4t\n")
	if err := promoteFamilies(esp); err != nil {
		t.Fatal(err)
	}
	if read(esp, "kernelcache-prev.l4t.efi") != "l4t-a" {
		t.Fatal("a family already promoted was rotated again")
	}
	if read(esp, familiesPending) != "<none>" {
		t.Fatal("marker left behind")
	}
}
