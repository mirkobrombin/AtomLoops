package otad

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

func liveMachine(t *testing.T, edit func(*Manifest)) (string, StageDirs, []byte) {
	t.Helper()
	base, rootPub := signedFeedWith(t, "verity-v2", edit)
	wal := e2eWAL(t)
	dirs := StageDirs{Rootfs: filepath.Join(t.TempDir(), "rootfs"), ESP: filepath.Join(t.TempDir(), "esp")}
	os.MkdirAll(dirs.Rootfs, 0o755)
	os.MkdirAll(dirs.ESP, 0o755)
	for _, f := range []string{filepath.Join(dirs.Rootfs, "rootfs-active.erofs"), filepath.Join(dirs.Rootfs, "rootfs-active.hash"),
		filepath.Join(dirs.ESP, "kernelcache-active.efi"), filepath.Join(dirs.ESP, "kernelcache-active.efi.sig")} {
		os.WriteFile(f, []byte("v1 "+filepath.Base(f)), 0o644)
	}
	bootedAs(t, "v1", "verity-v1")
	if _, err := Stage(context.Background(), wal, base+"/manifest.json", "", rootPub, dirs); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	return wal, dirs, rootPub
}

func TestLiveCandidateNeedsTheReleaseToAllowIt(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	kernel := RunningKernel()
	cases := []struct {
		name     string
		edit     func(*Manifest)
		eligible bool
	}{
		{"reboot only", func(m *Manifest) { m.KernelRelease = kernel }, false},
		{"live from v1", func(m *Manifest) {
			m.KernelRelease = kernel
			m.Apply = &ApplySpec{Class: "reload", LiveFrom: "v1"}
		}, true},
		{"live from another release", func(m *Manifest) {
			m.KernelRelease = kernel
			m.Apply = &ApplySpec{Class: "reload", LiveFrom: "v0"}
		}, false},
		{"another kernel", func(m *Manifest) {
			m.KernelRelease = kernel + "-other"
			m.Apply = &ApplySpec{Class: "reload", LiveFrom: "v1"}
		}, false},
		{"no kernel named", func(m *Manifest) { m.Apply = &ApplySpec{Class: "reload", LiveFrom: "v1"} }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wal, dirs, rootPub := liveMachine(t, c.edit)
			got, err := LiveCandidateOf(wal, dirs, rootPub)
			if err != nil {
				t.Fatal(err)
			}
			if got.Offer.Eligible != c.eligible {
				t.Fatalf("eligible=%v want %v: %+v", got.Offer.Eligible, c.eligible, got.Offer)
			}
			if c.eligible && (got.Offer.Class != "reload" || got.Offer.From != "v1" || got.Offer.To != "v2" || got.RootHash != "verity-v2") {
				t.Fatalf("offer %+v", got)
			}
		})
	}
}

func TestLiveCandidateRefusesWhatIsAlreadyRunning(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	wal, dirs, rootPub := liveMachine(t, func(m *Manifest) {
		m.KernelRelease = RunningKernel()
		m.Apply = &ApplySpec{Class: "reload", LiveFrom: "v1"}
	})
	if err := WriteLiveIdentity("v2", "verity-v2"); err != nil {
		t.Fatal(err)
	}
	got, _ := LiveCandidateOf(wal, dirs, rootPub)
	if got.Offer.Eligible {
		t.Fatalf("offered the running root again: %+v", got.Offer)
	}
}

func TestCommitLiveCountsAsGoodBoots(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	wal, dirs, rootPub := liveMachine(t, func(m *Manifest) {
		m.KernelRelease = RunningKernel()
		m.Apply = &ApplySpec{Class: "reload", LiveFrom: "v1"}
	})
	if _, err := CommitLive(wal, dirs, nil); err == nil {
		t.Fatal("committed while the old root still runs")
	}
	if err := WriteLiveIdentity("v2", "verity-v2"); err != nil {
		t.Fatal(err)
	}
	if _, err := CommitLive(wal, dirs, nil); err != nil {
		t.Fatal(err)
	}
	d, _ := deployment.Load(wal)
	if d.RootFS.Current != "v2" || d.RootFS.Pending != "v2" || d.Kernelcache.StableBoots != 1 {
		t.Fatalf("after one live apply: %+v %+v", d.RootFS, d.Kernelcache)
	}
	bs, err := ReadBootState(filepath.Join(dirs.ESP, "boot-state"))
	if err != nil || bs.Target != "next" {
		t.Fatalf("the next boot must still try the candidate: %+v %v", bs, err)
	}
	if got, _ := LiveCandidateOf(wal, dirs, rootPub); got.Offer.Eligible {
		t.Fatalf("offered again after applying: %+v", got.Offer)
	}
	health := t.TempDir()
	for i := 0; i < 2; i++ {
		if _, err := BootSuccess(wal, health, nil, dirs); err != nil {
			t.Fatal(err)
		}
	}
	d, _ = deployment.Load(wal)
	if d.HasPending() || d.RootFS.LastKnownGood != "v2" {
		t.Fatalf("not promoted after the remaining good boots: %+v", d.RootFS)
	}
	if b, _ := os.ReadFile(filepath.Join(dirs.Rootfs, "rootfs-active.erofs")); string(b) != "EROFS rootfs image v2" {
		t.Fatalf("active slot %q", b)
	}
}
