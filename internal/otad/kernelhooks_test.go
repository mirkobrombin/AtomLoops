package otad

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

// kernelHook installs a hook that records its phase, version and the content of
// the kernelcache it was handed, or fails when fail is set.
func kernelHook(t *testing.T, fail bool) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(t.TempDir(), "installed")
	script := "#!/bin/sh\nprintf '%s %s ' \"$1\" \"$ATOM_VERSION\" >> " + log + "\ncat \"$ATOM_KERNELCACHE\" >> " + log + "\necho >> " + log + "\n"
	if fail {
		script = "#!/bin/sh\necho no boot partition >&2\nexit 1\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "50-boot"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := KernelHookDir
	KernelHookDir = dir
	t.Cleanup(func() { KernelHookDir = old })
	return log
}

func TestStageInstallsTheCandidateKernelFirst(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	log := kernelHook(t, false)
	base, rootPub := signedFeedV2(t, "verity-v2")
	wal := e2eWAL(t)
	if _, err := Stage(context.Background(), wal, base+"/manifest.json", "", rootPub, installedDirs(t)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if b, _ := os.ReadFile(log); string(b) != "staged v2 UKI kernelcache v2\n" {
		t.Fatalf("hook saw %q", b)
	}
}

func TestStageRefusesACandidateWhoseKernelCannotBeInstalled(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	kernelHook(t, true)
	base, rootPub := signedFeedV2(t, "verity-v2")
	wal := e2eWAL(t)
	_, err := Stage(context.Background(), wal, base+"/manifest.json", "", rootPub, installedDirs(t))
	if err == nil || !strings.Contains(err.Error(), "no boot partition") {
		t.Fatalf("Stage: %v", err)
	}
	if d, _ := deployment.Load(wal); d.HasPending() {
		t.Fatal("a candidate whose kernel was not installed was marked pending")
	}
}

func TestSyncBootedKernelInstallsTheBootedReleasesKernel(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	_, dirs, rootPub := liveMachine(t, nil)
	log := kernelHook(t, false)
	old := BootIdentityPath
	BootIdentityPath = filepath.Join(t.TempDir(), "boot-identity")
	defer func() { BootIdentityPath = old }()

	if err := SyncBootedKernel(dirs.Rootfs, dirs.ESP, rootPub); err != nil {
		t.Fatalf("a boot through a loader: %v", err)
	}
	if _, err := os.Stat(log); err == nil {
		t.Fatal("a boot without an anchor identity ran the kernel hooks")
	}
	if err := WriteBootIdentity("verity-v2", "v2"); err != nil {
		t.Fatal(err)
	}
	if err := SyncBootedKernel(dirs.Rootfs, dirs.ESP, rootPub); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(log); string(b) != "booted v2 UKI kernelcache v2\n" {
		t.Fatalf("hook saw %q", b)
	}
	os.WriteFile(filepath.Join(dirs.ESP, "kernelcache-next.efi"), []byte("tampered"), 0o644)
	if err := SyncBootedKernel(dirs.Rootfs, dirs.ESP, rootPub); err == nil {
		t.Fatal("a kernelcache that does not match the signed manifest was installed")
	}
}
