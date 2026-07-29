// Package otad is the Atom Loops OTA daemon: the running-system half of the
// deployment.json WAL protocol. It records good boots (greenboot-style boot
// success gated on health checks), promotes a candidate to last_known_good once
// it stabilizes, and exposes deploy/rollback/status verbs over the WAL. It runs
// as a service under the init system; it never runs as PID 1 itself.
//
// The initramfs half (pick target, decrement boot_attempts, roll back on a spent
// budget) lives in the early-boot engine and shares the deployment package.
package otad

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

// healthTimeout bounds a single health-check script.
var healthTimeout = 30 * time.Second

// Init creates a fresh WAL for a device booting rootfsVersion as its first image
// (its own last_known_good). Used at provisioning / first boot.
func Init(walPath, deviceID, rootfsVersion string) (string, error) {
	d := deployment.New(deviceID, rootfsVersion)
	if err := d.Save(walPath); err != nil {
		return "", err
	}
	return fmt.Sprintf("initialized WAL %s: current=%s device=%s", walPath, rootfsVersion, deviceID), nil
}

// BootSuccess is the greenboot step, run once the system is up. With a candidate
// in flight it runs the health gate and, on success, records the good boot
// (switching to the candidate on its first good boot and promoting it once it
// reaches stable_threshold). With no candidate in flight it is a no-op. A failed
// health gate leaves the WAL untouched, so boot_attempts continues to drain and
// the initramfs will roll the candidate back on a later boot.
// bootIdentity is baked into the signed UKI cmdline. The root hash identifies the
// rootfs while the version distinguishes releases that reuse the same rootfs.
type bootIdentity struct {
	VerityHash string
	Version    string
}

var bootedVersionPath = "/proc/cmdline" // overridable in tests

// SetBootedCmdlinePath overrides the file the booted-identity check reads the kernel
// cmdline from, returning a function that restores the previous value. For tests and
// diagnostics.
func SetBootedCmdlinePath(p string) (restore func()) {
	old := bootedVersionPath
	bootedVersionPath = p
	return func() { bootedVersionPath = old }
}

func bootedIdentity() bootIdentity {
	b, err := os.ReadFile(bootedVersionPath)
	if err != nil {
		return bootIdentity{}
	}
	var id bootIdentity
	for _, tok := range strings.Fields(string(b)) {
		if v, ok := strings.CutPrefix(tok, "ATOM_ROOT_HASH="); ok {
			id.VerityHash = v
		}
		if v, ok := strings.CutPrefix(tok, "sing.roothash="); ok {
			id.VerityHash = v
		}
		if v, ok := strings.CutPrefix(tok, "ATOM_VERSION="); ok {
			id.Version = v
		}
		if v, ok := strings.CutPrefix(tok, "atom.version="); ok {
			id.Version = v
		}
	}
	return id
}

func BootSuccess(walPath, healthDir string, store CounterStore, dirs StageDirs) (string, error) {
	d, err := deployment.Load(walPath)
	if err != nil {
		return "", err
	}
	if !d.HasPending() {
		// Reconcile the hardware anti-rollback counter with the WAL. promote() sets
		// AntiRollback.CounterValue and Saves the WAL BEFORE store.Advance runs; a crash in
		// that window would leave the hardware floor behind the WAL. Retry it here (Advance is
		// monotonic -> a no-op once armed), so the floor eventually catches up on any later boot.
		if store != nil && d.AntiRollback.CounterValue > 0 {
			if cur, rerr := store.Read(); rerr == nil && cur < uint64(d.AntiRollback.CounterValue) {
				_ = store.Advance(uint64(d.AntiRollback.CounterValue))
			}
		}
		if err := writeDeploymentBootState(d, dirs); err != nil {
			return "", fmt.Errorf("stable boot-state reconciliation failed: %w", err)
		}
		syscall.Sync()
		CleanupNextSlots(dirs)
		syscall.Sync()
		return "stable: no candidate in flight, nothing to confirm", nil
	}
	if err := RunHealthChecks(healthDir); err != nil {
		return "", fmt.Errorf("health gate failed, candidate left unconfirmed: %w", err)
	}
	cand := d.RootFS.Pending
	// Only confirm the candidate if the RUNNING system IS the candidate. The loader
	// can silently fall back to -active when the trial budget is spent; without this check a
	// fallback boot of the old-good image would be counted as a "good boot" for the candidate
	// and eventually promote a dead candidate. The signed UKI command line in /proc/cmdline
	// binds both the root hash and release label to the running image.
	bi := bootedIdentity()
	identityConfirmed := bi.VerityHash != "" &&
		d.RootFS.PendingHash != "" &&
		bi.VerityHash == d.RootFS.PendingHash &&
		bi.Version != "" &&
		bi.Version == d.RootFS.Pending
	if !identityConfirmed {
		d.Kernelcache.StableBoots = 0
		reconciled := false
		if dirs.ESP != "" {
			bs, rerr := ReadBootState(filepath.Join(dirs.ESP, "boot-state"))
			if rerr == nil {
				switch {
				case bs.Target == "active":
					d.RootFS.BootAttempts = 0
					reconciled = true
				case bs.Target == "next" && bs.Trial && bs.Attempts <= d.RootFS.BootAttempts:
					d.RootFS.BootAttempts = bs.Attempts
					reconciled = true
				}
			}
		}
		exhausted := d.RootFS.BootAttempts <= 0
		if !reconciled {
			exhausted = d.DecrementBootAttempt()
		}
		if exhausted {
			d.Rollback() // budget spent and the candidate never booted -> return to last_known_good
		}
		if err := writeDeploymentBootState(d, dirs); err != nil {
			return "", fmt.Errorf("candidate %s fallback boot-state commit failed: %w", cand, err)
		}
		syscall.Sync()
		if err := d.Save(walPath); err != nil {
			return "", err
		}
		if exhausted {
			CleanupNextSlots(dirs)
			syscall.Sync()
		}
		return fmt.Sprintf("candidate %s did NOT boot (booted identity version=%s hash=%s, pending version=%s hash=%s); failed attempt recorded (exhausted=%v)",
			cand, bi.Version, bi.VerityHash, d.RootFS.Pending, d.RootFS.PendingHash, exhausted), nil
	}
	promoted := d.RecordGoodBoot(identityConfirmed)
	if promoted {
		if err := PromoteSlots(dirs); err != nil {
			return "", fmt.Errorf("candidate %s slot promotion failed: %w", cand, err)
		}
		// FAT directory fsync may return EINVAL even though the rename is still
		// buffered by the guest kernel. Flush the slot transaction before the WAL
		// can declare it committed.
		syscall.Sync()
		if dirs.ESP != "" {
			if err := WriteBootState(filepath.Join(dirs.ESP, "boot-state"), BootState{Target: "active"}); err != nil {
				return "", fmt.Errorf("candidate %s boot-state commit failed: %w", cand, err)
			}
		}
		syscall.Sync()
		if err := d.Save(walPath); err != nil {
			return "", err
		}
		CleanupNextSlots(dirs)
		syscall.Sync()
		if store != nil {
			if err := store.Advance(uint64(d.AntiRollback.CounterValue)); err != nil {
				return "", fmt.Errorf("promoted %s but arming anti-rollback counter failed: %w", cand, err)
			}
		}
		return fmt.Sprintf("candidate %s promoted to last_known_good (anti-rollback counter %d)",
			cand, d.AntiRollback.CounterValue), nil
	}
	if err := writeDeploymentBootState(d, dirs); err != nil {
		return "", fmt.Errorf("candidate %s trial boot-state commit failed: %w", cand, err)
	}
	syscall.Sync()
	if err := d.Save(walPath); err != nil {
		return "", err
	}
	return fmt.Sprintf("good boot recorded for candidate %s (%d/%d stable)",
		cand, d.Kernelcache.StableBoots, d.Kernelcache.StableThreshold), nil
}

// RunHealthChecks runs every executable in dir (sorted), each bounded by
// healthTimeout; all must exit 0. A missing directory or one with no executables
// counts as healthy (no checks configured).
func RunHealthChecks(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// A missing health dir counts as healthy: health checks are opt-in, and
			// failing closed here would roll back every update on a system that
			// configures none. Narrowed by the check above: only the candidate that is
			// actually running is ever promoted.
			return nil
		}
		return err
	}
	var scripts []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Mode()&0o111 == 0 {
			continue
		}
		scripts = append(scripts, filepath.Join(dir, e.Name()))
	}
	sort.Strings(scripts)
	for _, s := range scripts {
		ctx, cancel := context.WithTimeout(context.Background(), healthTimeout)
		err := exec.CommandContext(ctx, s).Run()
		cancel()
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(s), err)
		}
	}
	return nil
}

// Deploy stages a candidate version in the WAL and arms the boot budget. NOTE:
// this is the WAL transition only; downloading, verifying, and placing the rootfs
// and kernelcache artifacts on disk is the daemon's staging step (not yet built).
func Deploy(walPath, version string) (string, error) {
	d, err := deployment.Load(walPath)
	if err != nil {
		return "", err
	}
	d.Deploy(version)
	if err := d.Save(walPath); err != nil {
		return "", err
	}
	return fmt.Sprintf("staged candidate %s (boot_attempts=%d); reboot to try it",
		version, d.RootFS.BootAttempts), nil
}

// FirmwareBootConfirm advances the firmware track on the independent OTA cadence,
// separate from the rootfs BootSuccess path. probeOK is the daemon's device-probe
// result: whether the freshly-booted firmware actually bound its hardware. A failed
// probe rolls the firmware image, hash and anchor back to the previous good slot (the
// base survival firmware kept the device usable meanwhile); a clean probe records a
// good boot and, once the stable threshold is met, finalizes by dropping the backups.
// The on-disk slot ops mirror the WAL transitions so the two never diverge.
func FirmwareBootConfirm(walPath string, dirs StageDirs, bundle string, probeOK bool) (string, error) {
	d, err := deployment.Load(walPath)
	if err != nil {
		return "", err
	}
	if !d.HasPendingFirmware(bundle) {
		return fmt.Sprintf("firmware bundle %q: no candidate in flight", bundle), nil
	}
	bdir := filepath.Join(dirs.Firmware, bundle)
	if !probeOK {
		d.RollbackFirmware(bundle)
		if err := d.Save(walPath); err != nil {
			return "", err
		}
		if err := RollbackFirmwareSlot(bdir); err != nil {
			return "", fmt.Errorf("firmware bundle %q WAL rolled back but slot restore failed: %w", bundle, err)
		}
		return fmt.Sprintf("firmware bundle %q failed device-probe, rolled back to previous firmware", bundle), nil
	}
	promoted := d.RecordFirmwareProbe(bundle)
	if err := d.Save(walPath); err != nil {
		return "", err
	}
	if promoted {
		if err := FinalizeFirmwareSlot(bdir); err != nil {
			return "", fmt.Errorf("firmware bundle %q promoted but dropping backups failed: %w", bundle, err)
		}
		return fmt.Sprintf("firmware bundle %q promoted to last known good", bundle), nil
	}
	return fmt.Sprintf("firmware bundle %q good probe recorded (not yet at stable threshold)", bundle), nil
}

// FirmwareBootConfirmAll applies the same device-probe result to every bundle with a
// candidate in flight, for a coarse v1 probe that cannot tell bundles apart (e.g. "any
// firmware overlay mounted"). It returns a joined summary; the first error stops it.
func FirmwareBootConfirmAll(walPath string, dirs StageDirs, probeOK bool) (string, error) {
	d, err := deployment.Load(walPath)
	if err != nil {
		return "", err
	}
	pending := d.PendingFirmwareBundles()
	if len(pending) == 0 {
		return "no firmware candidate in flight", nil
	}
	sort.Strings(pending)
	var msgs []string
	for _, name := range pending {
		msg, err := FirmwareBootConfirm(walPath, dirs, name, probeOK)
		if err != nil {
			return "", err
		}
		msgs = append(msgs, msg)
	}
	return strings.Join(msgs, "; "), nil
}

// Rollback abandons any candidate and returns to last_known_good.
func Rollback(walPath string, dirs StageDirs) (string, error) {
	d, err := deployment.Load(walPath)
	if err != nil {
		return "", err
	}
	d.Rollback()
	if err := writeDeploymentBootState(d, dirs); err != nil {
		return "", fmt.Errorf("rollback boot-state commit failed: %w", err)
	}
	if err := d.Save(walPath); err != nil {
		return "", err
	}
	return fmt.Sprintf("rolled back to %s", d.RootFS.Current), nil
}

// Status returns a human-readable summary of the WAL.
func Status(walPath string) (string, error) {
	d, err := deployment.Load(walPath)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "current:         %s (kc %d)\n", d.RootFS.Current, d.Kernelcache.CurrentVersion)
	if d.HasPending() {
		fmt.Fprintf(&b, "pending:         %s (boot_attempts %d/%d, stable %d/%d)\n",
			d.RootFS.Pending, d.RootFS.BootAttempts, d.RootFS.MaxAttempts,
			d.Kernelcache.StableBoots, d.Kernelcache.StableThreshold)
	} else {
		fmt.Fprintf(&b, "pending:         none (%s)\n", d.Kernelcache.State)
	}
	fmt.Fprintf(&b, "rollback:        %s\n", d.RootFS.Rollback)
	fmt.Fprintf(&b, "last_known_good: %s (%s)\n", d.RootFS.LastKnownGood, d.RootFS.LastKnownGoodAt)
	fmt.Fprintf(&b, "recovery:        %s\n", d.Recovery.Version)
	fmt.Fprintf(&b, "security level:  L%d\n", d.Security.Level)
	fmt.Fprintf(&b, "anti-rollback:   %s counter=%d", d.AntiRollback.Hardware, d.AntiRollback.CounterValue)
	if len(d.Firmware.Bundles) == 0 {
		fmt.Fprintf(&b, "\nfirmware:        none")
		return b.String(), nil
	}
	names := make([]string, 0, len(d.Firmware.Bundles))
	for name := range d.Firmware.Bundles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fw := d.Firmware.Bundles[name]
		if d.HasPendingFirmware(name) {
			fmt.Fprintf(&b, "\nfirmware[%s]:    current v%d, pending v%d (probes %d/%d)",
				name, fw.CurrentVersion, fw.PendingVersion, fw.ProbeConfirms, fw.StableThreshold)
		} else {
			fmt.Fprintf(&b, "\nfirmware[%s]:    current v%d (no candidate)", name, fw.CurrentVersion)
		}
	}
	return b.String(), nil
}
