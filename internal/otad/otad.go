// Package otad is the Atom Loops OTA daemon: the running-system half of the
// deployment.json WAL protocol. It records good boots (greenboot-style boot
// success gated on health checks), promotes a candidate to last_known_good once
// it stabilizes, and exposes deploy/rollback/status verbs over the WAL. It runs
// as a service under the init (sinit); it never runs as PID 1 itself.
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
func BootSuccess(walPath, healthDir string, store CounterStore) (string, error) {
	d, err := deployment.Load(walPath)
	if err != nil {
		return "", err
	}
	if !d.HasPending() {
		return "stable: no candidate in flight, nothing to confirm", nil
	}
	if err := RunHealthChecks(healthDir); err != nil {
		return "", fmt.Errorf("health gate failed, candidate left unconfirmed: %w", err)
	}
	cand := d.RootFS.Pending
	promoted := d.RecordGoodBoot()
	if err := d.Save(walPath); err != nil {
		return "", err
	}
	if promoted {
		// Arm the monotonic anti-rollback counter only now, after the candidate has
		// stabilized (A4.2), so a faulty update never advances the floor.
		if store != nil {
			if err := store.Advance(uint64(d.AntiRollback.CounterValue)); err != nil {
				return "", fmt.Errorf("promoted %s but arming anti-rollback counter failed: %w", cand, err)
			}
		}
		return fmt.Sprintf("candidate %s promoted to last_known_good (anti-rollback counter %d)",
			cand, d.AntiRollback.CounterValue), nil
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

// Rollback abandons any candidate and returns to last_known_good.
func Rollback(walPath string) (string, error) {
	d, err := deployment.Load(walPath)
	if err != nil {
		return "", err
	}
	d.Rollback()
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
	return b.String(), nil
}
