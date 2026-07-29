package otad

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

func writeScript(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func newWAL(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := deployment.New("dev-1", "v1").Save(path); err != nil {
		t.Fatal(err)
	}
	return path
}

// confirmBootedIdentity points the booted-identity check at the pending candidate.
func confirmBootedIdentity(t *testing.T, wal, h string) func() {
	t.Helper()
	d, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	d.RootFS.PendingHash = h
	if err := d.Save(wal); err != nil {
		t.Fatal(err)
	}
	bv := filepath.Join(t.TempDir(), "cmdline")
	if err := os.WriteFile(bv, []byte("console=ttyS0 ATOM_ROOT_HASH="+h+" ATOM_VERSION="+d.RootFS.Pending+" ro\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return SetBootedCmdlinePath(bv)
}

func TestRunHealthChecks(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	// Missing directory counts as healthy.
	if err := RunHealthChecks(filepath.Join(t.TempDir(), "nope")); err != nil {
		t.Errorf("missing health dir should pass, got %v", err)
	}
	// A passing check.
	pass := t.TempDir()
	writeScript(t, filepath.Join(pass, "10-ok"), "exit 0")
	if err := RunHealthChecks(pass); err != nil {
		t.Errorf("passing check should pass, got %v", err)
	}
	// A failing check fails the gate.
	fail := t.TempDir()
	writeScript(t, filepath.Join(fail, "10-ok"), "exit 0")
	writeScript(t, filepath.Join(fail, "20-bad"), "exit 1")
	if err := RunHealthChecks(fail); err == nil {
		t.Error("failing check should fail the gate")
	}
}

func TestBootSuccessPromotes(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	wal := newWAL(t)
	if _, err := Deploy(wal, "v2"); err != nil {
		t.Fatal(err)
	}
	defer confirmBootedIdentity(t, wal, "hash-v2")()
	health := t.TempDir() // empty => healthy

	// Three good boots promote the candidate.
	var last string
	for i := 0; i < 3; i++ {
		msg, err := BootSuccess(wal, health, nil, StageDirs{})
		if err != nil {
			t.Fatalf("BootSuccess %d: %v", i, err)
		}
		last = msg
	}
	if !strings.Contains(last, "promoted") {
		t.Errorf("third boot message = %q, want it to report promotion", last)
	}
	d, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	if d.HasPending() || d.RootFS.Current != "v2" || d.RootFS.LastKnownGood != "v2" {
		t.Fatalf("WAL not promoted: %+v", d.RootFS)
	}
}

func TestBootSuccessDoesNotCommitWALWhenSlotPromotionFails(t *testing.T) {
	wal := newWAL(t)
	if _, err := Deploy(wal, "v2"); err != nil {
		t.Fatal(err)
	}
	defer confirmBootedIdentity(t, wal, "hash-v2")()
	d, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	d.Kernelcache.StableThreshold = 1
	if err := d.Save(wal); err != nil {
		t.Fatal(err)
	}
	rfs := t.TempDir()
	os.WriteFile(filepath.Join(rfs, "rootfs-active.erofs"), []byte("rfs-active"), 0o644)
	os.WriteFile(filepath.Join(rfs, "rootfs-active.hash"), []byte("hash-active"), 0o644)
	os.WriteFile(filepath.Join(rfs, "rootfs-next.erofs"), []byte("rfs-next"), 0o644)

	if _, err := BootSuccess(wal, t.TempDir(), nil, StageDirs{Rootfs: rfs}); err == nil {
		t.Fatal("BootSuccess accepted a failed slot promotion")
	}
	after, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	if after.RootFS.Pending != "v2" || after.RootFS.Current != "v1" || after.RootFS.LastKnownGood != "v1" {
		t.Fatalf("failed slot promotion committed the WAL: %+v", after.RootFS)
	}
}

func TestBootSuccessDoesNotCommitGoodBootWhenBootStateFails(t *testing.T) {
	wal := newWAL(t)
	if _, err := Deploy(wal, "v2"); err != nil {
		t.Fatal(err)
	}
	defer confirmBootedIdentity(t, wal, "hash-v2")()
	notDir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(notDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := BootSuccess(wal, t.TempDir(), nil, StageDirs{ESP: notDir}); err == nil {
		t.Fatal("BootSuccess committed despite a boot-state write failure")
	}
	after, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	if after.RootFS.Current != "v1" || after.RootFS.Pending != "v2" || after.Kernelcache.StableBoots != 0 {
		t.Fatalf("failed boot-state write committed good-boot progress: %+v", after.RootFS)
	}
}

// When the booted identity cannot be proven, promotion must never fire.
func TestBootSuccessUnknownIdentityNeverPromotes(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	wal := newWAL(t)
	if _, err := Deploy(wal, "v2"); err != nil {
		t.Fatal(err)
	}
	bv := filepath.Join(t.TempDir(), "cmdline")
	if err := os.WriteFile(bv, []byte("console=ttyS0 ro\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := bootedVersionPath
	bootedVersionPath = bv
	defer func() { bootedVersionPath = old }()

	health := t.TempDir()
	for i := 0; i < 6; i++ {
		msg, err := BootSuccess(wal, health, nil, StageDirs{})
		if err != nil {
			t.Fatalf("BootSuccess %d: %v", i, err)
		}
		if strings.Contains(msg, "promoted") {
			t.Fatalf("boot %d promoted an unverifiable candidate: %q", i, msg)
		}
	}
	d, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	if d.RootFS.LastKnownGood == "v2" || d.AntiRollback.CounterValue != 0 {
		t.Fatalf("unverifiable candidate promoted (brick risk): lkg=%s ctr=%d", d.RootFS.LastKnownGood, d.AntiRollback.CounterValue)
	}
}

// A candidate that never actually booted (loader fell back to the old image)
// must NOT be confirmed/promoted, no matter how many healthy fallback boots occur.
func TestBootSuccessRejectsFallbackCandidate(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	wal := newWAL(t)
	if _, err := Deploy(wal, "v2"); err != nil {
		t.Fatal(err)
	}
	// The candidate v2 has verity hash "hash-v2" (as stage.go would record from the manifest).
	d0, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	d0.RootFS.PendingHash = "hash-v2"
	if err := d0.Save(wal); err != nil {
		t.Fatal(err)
	}
	health := t.TempDir() // empty => healthy

	// The loader fell back: the running cmdline carries hash-v1, NOT the candidate's hash-v2.
	bv := filepath.Join(t.TempDir(), "cmdline")
	if err := os.WriteFile(bv, []byte("console=ttyS0 ATOM_ROOT_HASH=hash-v1 ATOM_VERSION=v1 ro\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := bootedVersionPath
	bootedVersionPath = bv
	defer func() { bootedVersionPath = old }()

	for i := 0; i < 5; i++ {
		msg, err := BootSuccess(wal, health, nil, StageDirs{})
		if err != nil {
			t.Fatalf("BootSuccess %d: %v", i, err)
		}
		if strings.Contains(msg, "promoted") {
			t.Fatalf("boot %d PROMOTED a candidate that never ran: %q", i, msg)
		}
	}
	d, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	if d.RootFS.Current == "v2" || d.RootFS.LastKnownGood == "v2" {
		t.Fatalf("dead candidate v2 promoted despite never running: %+v", d.RootFS)
	}
}

func TestBootSuccessRejectsFallbackWithReusedRootFS(t *testing.T) {
	wal := newWAL(t)
	if _, err := Deploy(wal, "v2"); err != nil {
		t.Fatal(err)
	}
	d, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	d.RootFS.PendingHash = "shared-hash"
	if err := d.Save(wal); err != nil {
		t.Fatal(err)
	}
	bv := filepath.Join(t.TempDir(), "cmdline")
	if err := os.WriteFile(bv, []byte("ATOM_ROOT_HASH=shared-hash ATOM_VERSION=v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer SetBootedCmdlinePath(bv)()

	msg, err := BootSuccess(wal, t.TempDir(), nil, StageDirs{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msg, "good boot") || strings.Contains(msg, "promoted") {
		t.Fatalf("fallback with reused rootfs accepted as candidate: %q", msg)
	}
	after, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	if after.RootFS.Current != "v1" || after.Kernelcache.StableBoots != 0 || after.RootFS.BootAttempts != 2 {
		t.Fatalf("fallback identity was not rejected: %+v", after.RootFS)
	}
}

func TestBootSuccessReconcilesExhaustedLoaderBudget(t *testing.T) {
	wal := newWAL(t)
	if _, err := Deploy(wal, "v2"); err != nil {
		t.Fatal(err)
	}
	d, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	d.RootFS.PendingHash = "hash-v2"
	if err := d.Save(wal); err != nil {
		t.Fatal(err)
	}
	bv := filepath.Join(t.TempDir(), "cmdline")
	if err := os.WriteFile(bv, []byte("ATOM_ROOT_HASH=hash-v1 ATOM_VERSION=v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer SetBootedCmdlinePath(bv)()
	esp := t.TempDir()
	rootfs := t.TempDir()
	if err := WriteBootState(filepath.Join(esp, "boot-state"),
		BootState{Target: "next", Trial: true, Attempts: 0}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(esp, "kernelcache-next.efi"),
		filepath.Join(esp, "kernelcache-next.efi.sig"),
		filepath.Join(rootfs, "rootfs-next.erofs"),
		filepath.Join(rootfs, "rootfs-next.hash"),
	} {
		if err := os.WriteFile(path, []byte("stale candidate"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := BootSuccess(wal, t.TempDir(), nil, StageDirs{ESP: esp, Rootfs: rootfs}); err != nil {
		t.Fatal(err)
	}
	after, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	if after.HasPending() || after.RootFS.Current != "v1" || after.RootFS.BootAttempts != 0 {
		t.Fatalf("spent loader budget did not roll back the WAL: %+v", after.RootFS)
	}
	bs, err := ReadBootState(filepath.Join(esp, "boot-state"))
	if err != nil {
		t.Fatal(err)
	}
	if bs.Target != "active" || bs.Trial {
		t.Fatalf("rollback did not disarm the loader: %+v", bs)
	}
	for _, path := range []string{
		filepath.Join(esp, "kernelcache-next.efi"),
		filepath.Join(esp, "kernelcache-next.efi.sig"),
		filepath.Join(rootfs, "rootfs-next.erofs"),
		filepath.Join(rootfs, "rootfs-next.hash"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("rollback left stale candidate slot %s: %v", path, err)
		}
	}
}

func TestBootSuccessReconcilesActiveBootStateAfterInterruptedRollback(t *testing.T) {
	wal := newWAL(t)
	if _, err := Deploy(wal, "v2"); err != nil {
		t.Fatal(err)
	}
	d, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	d.RootFS.PendingHash = "hash-v2"
	if err := d.Save(wal); err != nil {
		t.Fatal(err)
	}
	bv := filepath.Join(t.TempDir(), "cmdline")
	if err := os.WriteFile(bv, []byte("ATOM_ROOT_HASH=hash-v1 ATOM_VERSION=v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer SetBootedCmdlinePath(bv)()
	esp := t.TempDir()
	if err := WriteBootState(filepath.Join(esp, "boot-state"), BootState{Target: "active"}); err != nil {
		t.Fatal(err)
	}

	if _, err := BootSuccess(wal, t.TempDir(), nil, StageDirs{ESP: esp}); err != nil {
		t.Fatal(err)
	}
	after, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	if after.HasPending() || after.RootFS.Current != "v1" {
		t.Fatalf("active loader state did not finish interrupted rollback: %+v", after.RootFS)
	}
}

func TestBootSuccessHealthGateFailsLeavesWALUntouched(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	wal := newWAL(t)
	if _, err := Deploy(wal, "v2"); err != nil {
		t.Fatal(err)
	}
	before, _ := deployment.Load(wal)

	health := t.TempDir()
	writeScript(t, filepath.Join(health, "10-bad"), "exit 1")
	if _, err := BootSuccess(wal, health, nil, StageDirs{}); err == nil {
		t.Fatal("BootSuccess should fail when the health gate fails")
	}
	after, _ := deployment.Load(wal)
	// A failed gate must not record progress: stable_boots and current unchanged.
	if after.Kernelcache.StableBoots != before.Kernelcache.StableBoots ||
		after.RootFS.Current != before.RootFS.Current {
		t.Errorf("failed health gate mutated the WAL: before=%+v after=%+v", before.RootFS, after.RootFS)
	}
}

func TestBootSuccessNoCandidate(t *testing.T) {
	wal := newWAL(t)
	esp := t.TempDir()
	rfs := t.TempDir()
	for _, s := range []string{".efi", ".efi.sig"} {
		if err := os.WriteFile(filepath.Join(esp, "kernelcache-next"+s), []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []string{".erofs", ".hash"} {
		if err := os.WriteFile(filepath.Join(rfs, "rootfs-next"+s), []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	msg, err := BootSuccess(wal, filepath.Join(t.TempDir(), "none"), nil, StageDirs{ESP: esp, Rootfs: rfs})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "stable") {
		t.Errorf("no-candidate message = %q, want it to say stable", msg)
	}
	for _, s := range []string{".efi", ".efi.sig"} {
		if _, err := os.Stat(filepath.Join(esp, "kernelcache-next"+s)); !os.IsNotExist(err) {
			t.Errorf("stale next%s survived stable reconciliation", s)
		}
	}
	for _, s := range []string{".erofs", ".hash"} {
		if _, err := os.Stat(filepath.Join(rfs, "rootfs-next"+s)); !os.IsNotExist(err) {
			t.Errorf("stale next%s survived stable reconciliation", s)
		}
	}
}

func TestBootSuccessStableCleanupWaitsForBootState(t *testing.T) {
	wal := newWAL(t)
	d, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	d.AntiRollback.CounterValue = 5
	if err := d.Save(wal); err != nil {
		t.Fatal(err)
	}
	rfs := t.TempDir()
	next := filepath.Join(rfs, "rootfs-next.erofs")
	if err := os.WriteFile(next, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	counter := FileCounter{Path: filepath.Join(t.TempDir(), "counter")}
	notDir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(notDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := BootSuccess(wal, t.TempDir(), counter, StageDirs{ESP: notDir, Rootfs: rfs}); err == nil {
		t.Fatal("BootSuccess accepted a failed boot-state write")
	}
	if _, err := os.Stat(next); err != nil {
		t.Fatalf("next slot was removed before boot-state disarm succeeded: %v", err)
	}
	if got, err := counter.Read(); err != nil || got != 5 {
		t.Fatalf("counter reconciliation did not run before boot-state failure: got=%d err=%v", got, err)
	}
}

func TestDeployAndRollback(t *testing.T) {
	wal := newWAL(t)
	if _, err := Deploy(wal, "v2"); err != nil {
		t.Fatal(err)
	}
	d, _ := deployment.Load(wal)
	if d.RootFS.Pending != "v2" || d.RootFS.BootAttempts != 3 {
		t.Fatalf("deploy did not stage: %+v", d.RootFS)
	}
	if _, err := Rollback(wal, StageDirs{}); err != nil {
		t.Fatal(err)
	}
	d, _ = deployment.Load(wal)
	if d.HasPending() || d.RootFS.Current != "v1" {
		t.Fatalf("rollback did not return to v1: %+v", d.RootFS)
	}
	if s, err := Status(wal); err != nil || !strings.Contains(s, "current:") {
		t.Errorf("status = %q, err=%v", s, err)
	}
}

func TestRollbackDoesNotCommitWhenBootStateFails(t *testing.T) {
	wal := newWAL(t)
	if _, err := Deploy(wal, "v2"); err != nil {
		t.Fatal(err)
	}
	notDir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(notDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Rollback(wal, StageDirs{ESP: notDir}); err == nil {
		t.Fatal("Rollback committed despite a boot-state write failure")
	}
	after, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	if after.RootFS.Pending != "v2" || after.RootFS.Current != "v1" {
		t.Fatalf("failed boot-state write committed rollback: %+v", after.RootFS)
	}
}
