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

// confirmBootedIdentity marks the WAL's pending candidate with verity hash h and points
// the booted-identity check at a cmdline carrying it, so BootSuccess may promote it.
// Returns the cmdline-path restore func.
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
	if err := os.WriteFile(bv, []byte("console=ttyS0 ATOM_ROOT_HASH="+h+" ro\n"), 0o644); err != nil {
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

// When the booted identity cannot be proven (no ATOM_ROOT_HASH in the cmdline, no
// pending_hash), promotion must never fire, so the candidate can only roll back.
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
	if err := os.WriteFile(bv, []byte("console=ttyS0 ATOM_ROOT_HASH=hash-v1 ro\n"), 0o644); err != nil {
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
	msg, err := BootSuccess(wal, filepath.Join(t.TempDir(), "none"), nil, StageDirs{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "stable") {
		t.Errorf("no-candidate message = %q, want it to say stable", msg)
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
