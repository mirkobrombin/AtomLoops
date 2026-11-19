package otad

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnchorBootTriesTheCandidateThenTheInstalledRelease(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	wal, dirs, rootPub := liveMachine(t, nil)
	c, err := ChooseAnchorRoot(wal, dirs.Rootfs, dirs.ESP, rootPub)
	if err != nil || !c.Trial || c.Manifest.Version != "v2" || c.Manifest.RootFSVerityHash != "verity-v2" {
		t.Fatalf("candidate: %+v %v", c, err)
	}
	bs, _ := ReadBootState(filepath.Join(dirs.ESP, "boot-state"))
	for i := 0; i < bs.Attempts; i++ {
		if err := SpendAnchorTrial(dirs.ESP); err != nil {
			t.Fatal(err)
		}
	}
	if left, _ := ReadBootState(filepath.Join(dirs.ESP, "boot-state")); left.Attempts != 0 {
		t.Fatalf("attempts left %d", left.Attempts)
	}
	if _, err := ChooseAnchorRoot(wal, dirs.Rootfs, dirs.ESP, rootPub); err == nil {
		t.Fatal("a spent candidate with no kept installed release still yielded a root")
	}
}

func TestAnchorBootRunsTheInstalledRelease(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	wal, dirs, rootPub := promotedMachine(t)
	c, err := ChooseAnchorRoot(wal, dirs.Rootfs, dirs.ESP, rootPub)
	if err != nil || c.Trial || c.Manifest.Version != "v2" {
		t.Fatalf("installed: %+v %v", c, err)
	}
	m := filepath.Join(dirs.Rootfs, "release", "v2", "manifest.json")
	data, _ := os.ReadFile(m)
	os.WriteFile(m, append(data, ' '), 0o644)
	if _, err := ChooseAnchorRoot(wal, dirs.Rootfs, dirs.ESP, rootPub); err == nil {
		t.Fatal("a tampered anchor yielded a root")
	}
}

func TestAnchorBootIdentityConfirmsTheCandidate(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	wal, dirs, rootPub := liveMachine(t, nil)
	c, err := ChooseAnchorRoot(wal, dirs.Rootfs, dirs.ESP, rootPub)
	if err != nil {
		t.Fatal(err)
	}
	cmdline := filepath.Join(t.TempDir(), "cmdline")
	os.WriteFile(cmdline, []byte("sing.roothash=anchor\n"), 0o644)
	restore := SetBootedCmdlinePath(cmdline)
	defer restore()
	old := BootIdentityPath
	BootIdentityPath = filepath.Join(t.TempDir(), "boot-identity")
	defer func() { BootIdentityPath = old }()
	if err := SpendAnchorTrial(dirs.ESP); err != nil {
		t.Fatal(err)
	}
	if err := WriteBootIdentity(c.Manifest.RootFSVerityHash, c.Manifest.Version); err != nil {
		t.Fatal(err)
	}
	health := t.TempDir()
	for i := 0; i < 3; i++ {
		if _, err := BootSuccess(wal, health, nil, dirs); err != nil {
			t.Fatalf("BootSuccess: %v", err)
		}
	}
	if v, _ := InstalledVersion(wal); v != "v2" {
		t.Fatalf("installed %q, the anchor-booted candidate was not confirmed", v)
	}
}
