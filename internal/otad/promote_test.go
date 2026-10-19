package otad

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

func installedDirs(t *testing.T) StageDirs {
	t.Helper()
	dirs := StageDirs{Rootfs: filepath.Join(t.TempDir(), "rootfs"), ESP: filepath.Join(t.TempDir(), "esp")}
	for _, f := range []string{
		filepath.Join(dirs.Rootfs, "rootfs-active.erofs"),
		filepath.Join(dirs.Rootfs, "rootfs-active.hash"),
		filepath.Join(dirs.ESP, "kernelcache-active.efi"),
		filepath.Join(dirs.ESP, "kernelcache-active.efi.sig"),
	} {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte("v1 "+filepath.Base(f)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dirs
}

func TestStagePromotesTheRunningCandidate(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	base, rootPub := signedFeedV2(t, "verity-v2")
	wal := e2eWAL(t)
	dirs := installedDirs(t)
	if _, err := Stage(context.Background(), wal, base+"/manifest.json", "", rootPub, dirs); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	bootedAs(t, "v2", "verity-v2")
	if _, err := BootSuccess(wal, t.TempDir(), nil, StageDirs{}); err != nil {
		t.Fatalf("BootSuccess: %v", err)
	}
	d, _ := deployment.Load(wal)
	if !d.HasPending() || d.RootFS.LastKnownGood == "v2" {
		t.Fatalf("one good boot must not promote yet: %+v", d.RootFS)
	}
	if _, err := Stage(context.Background(), wal, base+"/manifest.json", "", rootPub, dirs); err != nil {
		t.Fatalf("second Stage: %v", err)
	}
	d, _ = deployment.Load(wal)
	if d.RootFS.LastKnownGood != "v2" {
		t.Fatalf("running candidate not promoted before staging the next one: %+v", d.RootFS)
	}
	if b, _ := os.ReadFile(filepath.Join(dirs.Rootfs, "rootfs-active.erofs")); string(b) != "EROFS rootfs image v2" {
		t.Fatalf("active rootfs slot = %q, want the promoted v2 image", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dirs.ESP, "kernelcache-active.efi")); string(b) != "UKI kernelcache v2" {
		t.Fatalf("active kernelcache = %q, want the promoted v2 kernelcache", b)
	}
	if !d.HasPending() {
		t.Fatal("the new candidate was not staged after the promotion")
	}
}

func TestStageKeepsAnUnconfirmedCandidatePending(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	base, rootPub := signedFeedV2(t, "verity-v2")
	wal := e2eWAL(t)
	dirs := installedDirs(t)
	if _, err := Stage(context.Background(), wal, base+"/manifest.json", "", rootPub, dirs); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	bootedAs(t, "v1", "verity-v1")
	if _, err := BootSuccess(wal, t.TempDir(), nil, StageDirs{}); err != nil {
		t.Fatalf("BootSuccess: %v", err)
	}
	if _, err := Stage(context.Background(), wal, base+"/manifest.json", "", rootPub, dirs); err != nil {
		t.Fatalf("second Stage: %v", err)
	}
	d, _ := deployment.Load(wal)
	if d.RootFS.LastKnownGood == "v2" {
		t.Fatalf("a candidate the machine never booted was promoted: %+v", d.RootFS)
	}
	if b, _ := os.ReadFile(filepath.Join(dirs.Rootfs, "rootfs-active.erofs")); string(b) != "v1 rootfs-active.erofs" {
		t.Fatalf("active rootfs slot = %q, an unbooted candidate reached it", b)
	}
}
