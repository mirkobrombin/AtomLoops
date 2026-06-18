package deployment

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func init() {
	// Deterministic timestamps in tests.
	nowFn = func() time.Time { return time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC) }
}

// a6_1Example is the deployment.json example from Atom Loops Architecture v4.6
// section A6.1. Unmarshaling it and checking fields locks our struct tags to the
// canonical schema (and proves null pending/pending_version decode cleanly).
const a6_1Example = `{
  "rootfs": {"current":"v43","pending":null,"rollback":"v42","boot_attempts":0,"max_attempts":3,"last_known_good":"v43","last_known_good_at":"2026-04-17T13:00:00Z"},
  "kernelcache": {"current_version":43,"pending_version":null,"state":"stable","stable_boots":0,"stable_threshold":3,"format":"uki"},
  "recovery": {"version":"r12","path":"ESP/EFI/atom/recovery.efi","last_updated":"2026-03-01T00:00:00Z"},
  "security": {"level":2,"dm_verity":true,"secure_boot":true,"ima":false,"signing_cert":"v2","remote_attestation":false},
  "anti_rollback": {"hardware":"tpm2","counter_value":43,"last_updated":"2026-04-17T14:00:00Z"},
  "orphan_homes": [],
  "recovery_entry": "recovery",
  "meta": {"schema_version":1,"device_id":"rpi4-abc123","channel":"stable","last_update_check":"2026-04-17T14:00:00Z"}
}`

func TestSchemaMatchesA61Example(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, []byte(a6_1Example), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Load(path)
	if err != nil {
		t.Fatalf("Load A6.1 example: %v", err)
	}
	checks := []struct {
		name string
		got  any
		want any
	}{
		{"rootfs.current", d.RootFS.Current, "v43"},
		{"rootfs.pending(null->\"\")", d.RootFS.Pending, ""},
		{"rootfs.rollback", d.RootFS.Rollback, "v42"},
		{"rootfs.max_attempts", d.RootFS.MaxAttempts, 3},
		{"rootfs.last_known_good", d.RootFS.LastKnownGood, "v43"},
		{"kernelcache.current_version", d.Kernelcache.CurrentVersion, 43},
		{"kernelcache.stable_threshold", d.Kernelcache.StableThreshold, 3},
		{"kernelcache.format", d.Kernelcache.Format, "uki"},
		{"recovery.path", d.Recovery.Path, "ESP/EFI/atom/recovery.efi"},
		{"security.level", d.Security.Level, 2},
		{"security.dm_verity", d.Security.DMVerity, true},
		{"anti_rollback.hardware", d.AntiRollback.Hardware, "tpm2"},
		{"recovery_entry", d.RecoveryEntry, "recovery"},
		{"meta.device_id", d.Meta.DeviceID, "rpi4-abc123"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestWALRoundTripAndSelfHeal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deployment.json")
	d := New("dev-1", "v1")
	if err := d.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Both primary and backup must exist and reload identically.
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.RootFS.Current != "v1" || got.Meta.DeviceID != "dev-1" {
		t.Fatalf("round-trip mismatch: %+v", got.RootFS)
	}
	if _, err := os.Stat(path + BakSuffix); err != nil {
		t.Fatalf("backup not written: %v", err)
	}
	// Corrupt the primary: Load must self-heal from .bak.
	if err := os.WriteFile(path, []byte("{ this is not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	healed, err := Load(path)
	if err != nil {
		t.Fatalf("Load should self-heal from .bak: %v", err)
	}
	if healed.RootFS.Current != "v1" {
		t.Errorf("self-healed current = %q, want v1", healed.RootFS.Current)
	}
	// With both primary and backup unreadable, Load must error, not panic.
	os.Remove(path + BakSuffix)
	if _, err := Load(path); err == nil {
		t.Error("Load should error when neither primary nor backup is valid")
	}
}

func TestDeployStabilizePromote(t *testing.T) {
	d := New("dev-1", "v1")
	d.Deploy("v2")

	if tgt, pending := d.BootVersion(); tgt != "v2" || !pending {
		t.Fatalf("BootVersion = %q,%v; want v2,true", tgt, pending)
	}
	if d.RootFS.BootAttempts != 3 || d.Kernelcache.State != KCUpdating {
		t.Fatalf("Deploy did not arm: attempts=%d state=%s", d.RootFS.BootAttempts, d.Kernelcache.State)
	}
	// Deploy must not touch current or last_known_good yet.
	if d.RootFS.Current != "v1" || d.RootFS.LastKnownGood != "v1" {
		t.Fatalf("Deploy changed current/lkg early: %+v", d.RootFS)
	}

	// Boot 1: initramfs spends an attempt; daemon records the good boot -> switch.
	d.DecrementBootAttempt()
	if promoted := d.RecordGoodBoot(); promoted {
		t.Fatal("promoted after 1 good boot, want 3")
	}
	if d.RootFS.Current != "v2" || d.RootFS.Rollback != "v1" || d.RootFS.LastKnownGood != "v1" {
		t.Fatalf("first good boot switch wrong: %+v", d.RootFS)
	}
	if d.RootFS.BootAttempts != 3 {
		t.Errorf("good boot did not refresh budget: %d", d.RootFS.BootAttempts)
	}

	// Boots 2 and 3.
	d.DecrementBootAttempt()
	d.RecordGoodBoot()
	d.DecrementBootAttempt()
	if promoted := d.RecordGoodBoot(); !promoted {
		t.Fatal("not promoted after 3 good boots")
	}
	if d.HasPending() || d.RootFS.LastKnownGood != "v2" || d.Kernelcache.State != KCStable {
		t.Fatalf("promotion state wrong: %+v / kc=%+v", d.RootFS, d.Kernelcache)
	}
	if d.AntiRollback.CounterValue != 2 {
		t.Errorf("anti-rollback counter = %d, want 2 (armed at promotion)", d.AntiRollback.CounterValue)
	}
	if d.RootFS.BootAttempts != 0 {
		t.Errorf("budget not disarmed after promotion: %d", d.RootFS.BootAttempts)
	}
}

func TestFailedCandidateRollsBack(t *testing.T) {
	d := New("dev-1", "v1")
	d.Deploy("v2")

	// One good boot switches to v2 (kernelcache 1 -> 2), then it starts failing.
	d.DecrementBootAttempt()
	d.RecordGoodBoot()
	if d.RootFS.Current != "v2" || d.Kernelcache.CurrentVersion != 2 {
		t.Fatalf("switch wrong: current=%s kc=%d", d.RootFS.Current, d.Kernelcache.CurrentVersion)
	}

	// The refreshed budget now drains to zero across consecutive failed boots.
	var exhausted bool
	for i := 0; i < 3; i++ {
		exhausted = d.DecrementBootAttempt()
	}
	if !exhausted {
		t.Fatalf("budget not exhausted after 3 failed boots: %d", d.RootFS.BootAttempts)
	}
	if d.NeedsRecovery() {
		t.Fatal("NeedsRecovery true but last_known_good v1 exists; should roll back, not recover")
	}
	d.Rollback()
	if d.RootFS.Current != "v1" || d.HasPending() || d.Kernelcache.State != KCStable {
		t.Fatalf("rollback state wrong: %+v", d.RootFS)
	}
	if d.Kernelcache.CurrentVersion != 1 {
		t.Errorf("kernelcache not reverted with rootfs (1:1 coupling): kc=%d, want 1", d.Kernelcache.CurrentVersion)
	}
}

func TestRecoveryWhenNoGoodFallback(t *testing.T) {
	// A candidate in flight with no last_known_good (e.g. first-ever image failing).
	d := New("dev-1", "v1")
	d.RootFS.LastKnownGood = ""
	d.RootFS.Rollback = ""
	d.Deploy("v2")
	for i := 0; i < 3; i++ {
		d.DecrementBootAttempt()
	}
	if !d.NeedsRecovery() {
		t.Fatalf("NeedsRecovery false but no fallback exists: attempts=%d lkg=%q", d.RootFS.BootAttempts, d.RootFS.LastKnownGood)
	}
}
