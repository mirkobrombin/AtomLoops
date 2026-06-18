package deployment

import (
	"strconv"
	"time"
)

// nowFn is the clock, swapped in tests for deterministic timestamps.
var nowFn = time.Now

// kcOf derives a kernelcache version from a rootfs version string. Per the v4.6
// review, rootfs and kernelcache versions are coupled 1:1 (rootfs "v43" <-> kc
// 43), so the kernelcache integer is the trailing digit run of the rootfs version.
// Returns ok=false when the version carries no trailing integer, in which case
// callers leave the kernelcache version untouched.
func kcOf(rootfsVersion string) (int, bool) {
	i := len(rootfsVersion)
	for i > 0 && rootfsVersion[i-1] >= '0' && rootfsVersion[i-1] <= '9' {
		i--
	}
	if i == len(rootfsVersion) {
		return 0, false
	}
	n, err := strconv.Atoi(rootfsVersion[i:])
	if err != nil {
		return 0, false
	}
	return n, true
}

func timestamp() string { return nowFn().UTC().Format(time.RFC3339) }

// New returns a fresh WAL for a device booting its first image, already stable
// (that image is its own last_known_good). The kernelcache version is derived
// from the rootfs version (coupled 1:1). Defaults: 3 boot attempts, 3 stable
// boots to promote, UKI kernelcache.
func New(deviceID, rootfsVersion string) *Deployment {
	kc, _ := kcOf(rootfsVersion)
	return &Deployment{
		RootFS: RootFS{
			Current:         rootfsVersion,
			MaxAttempts:     3,
			LastKnownGood:   rootfsVersion,
			LastKnownGoodAt: timestamp(),
		},
		Kernelcache: Kernelcache{
			CurrentVersion:  kc,
			State:           KCStable,
			StableThreshold: 3,
			Format:          "uki",
		},
		AntiRollback:  AntiRollback{Hardware: "none"},
		OrphanHomes:   []string{},
		RecoveryEntry: "recovery",
		Meta:          Meta{SchemaVersion: 1, DeviceID: deviceID, Channel: "stable"},
	}
}

// --- Daemon-side transitions (running system) ---

// Deploy stages a verified candidate as pending and arms the boot-attempt budget.
// It does NOT change current: the switch is recorded on the candidate's first
// good boot (RecordGoodBoot), so a candidate that never boots cleanly leaves
// current untouched. The kernelcache version is derived from the rootfs version
// (coupled 1:1). Call after the rootfs/kernelcache artifacts are on disk.
func (d *Deployment) Deploy(rootfsVersion string) {
	d.RootFS.Pending = rootfsVersion
	d.RootFS.BootAttempts = d.RootFS.MaxAttempts
	if kc, ok := kcOf(rootfsVersion); ok {
		d.Kernelcache.PendingVersion = kc
	}
	d.Kernelcache.State = KCUpdating
	d.Kernelcache.StableBoots = 0
}

// RecordGoodBoot is called by the daemon once the running system passes its
// health gate. On the candidate's first good boot it records the switch
// (current <- pending, rollback <- old current); every good boot refreshes the
// boot budget and advances stable_boots; at stable_threshold it promotes the
// candidate to last_known_good, disarms rollback, and arms the anti-rollback
// counter. Returns true on the boot that performs the promotion. No-op (false)
// on a stable system with no candidate in flight.
func (d *Deployment) RecordGoodBoot() (promoted bool) {
	if !d.HasPending() {
		return false
	}
	if d.RootFS.Current != d.RootFS.Pending {
		d.RootFS.Rollback = d.RootFS.Current
		d.RootFS.Current = d.RootFS.Pending
		d.Kernelcache.CurrentVersion = d.Kernelcache.PendingVersion
	}
	d.Kernelcache.StableBoots++
	d.RootFS.BootAttempts = d.RootFS.MaxAttempts // a good boot restores the budget
	if d.Kernelcache.StableBoots >= d.Kernelcache.StableThreshold {
		d.promote()
		return true
	}
	return false
}

func (d *Deployment) promote() {
	d.RootFS.LastKnownGood = d.RootFS.Current
	d.RootFS.LastKnownGoodAt = timestamp()
	d.RootFS.Pending = ""
	d.RootFS.BootAttempts = 0
	d.Kernelcache.PendingVersion = 0
	d.Kernelcache.StableBoots = 0
	d.Kernelcache.State = KCStable
	// The counter is advanced only here, after stable_threshold good boots, so a
	// faulty update can never move the hardware anti-rollback floor.
	d.AntiRollback.CounterValue = d.Kernelcache.CurrentVersion
	d.AntiRollback.LastUpdated = timestamp()
}

// --- Initramfs-side transitions (early boot) ---

// PickBootTarget returns the rootfs version the initramfs should boot and whether
// it is the pending candidate. Read-only.
func (d *Deployment) PickBootTarget() (version string, pending bool) {
	if d.HasPending() {
		return d.RootFS.Pending, true
	}
	return d.RootFS.Current, false
}

// DecrementBootAttempt is the single WAL write the initramfs performs each boot
// while a candidate is in flight: it spends one boot attempt and reports whether
// the budget is now exhausted (the caller must then Rollback, or enter Recovery
// if NeedsRecovery). With no candidate in flight it is a no-op returning false.
func (d *Deployment) DecrementBootAttempt() (exhausted bool) {
	if !d.HasPending() {
		return false
	}
	if d.RootFS.BootAttempts > 0 {
		d.RootFS.BootAttempts--
	}
	return d.RootFS.BootAttempts <= 0
}

// Rollback abandons the pending candidate and returns to last_known_good, the
// version guaranteed to have booted stable_threshold times; its artifacts are
// already on the device. Called by the initramfs when the boot budget is spent,
// or by the daemon on an explicit rollback. Because rootfs and kernelcache
// versions are coupled 1:1, the kernelcache version is reverted to match the
// rootfs it falls back to.
func (d *Deployment) Rollback() {
	switch {
	case d.RootFS.LastKnownGood != "":
		d.RootFS.Current = d.RootFS.LastKnownGood
	case d.RootFS.Rollback != "":
		d.RootFS.Current = d.RootFS.Rollback
	}
	if kc, ok := kcOf(d.RootFS.Current); ok {
		d.Kernelcache.CurrentVersion = kc
	}
	d.RootFS.Pending = ""
	d.RootFS.BootAttempts = 0
	d.Kernelcache.PendingVersion = 0
	d.Kernelcache.StableBoots = 0
	d.Kernelcache.State = KCStable
}

// NeedsRecovery reports that automatic rollback is impossible -- a candidate is
// in flight, the boot budget is spent, and there is no last_known_good to fall
// back to -- so the initramfs must enter Recovery.
func (d *Deployment) NeedsRecovery() bool {
	return d.HasPending() && d.RootFS.BootAttempts <= 0 && d.RootFS.LastKnownGood == ""
}
