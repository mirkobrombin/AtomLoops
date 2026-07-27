package otad

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

// SyncBootState writes the ESP boot-state to match the WAL: a pending candidate
// means boot the -next slot on its remaining boot budget; otherwise boot -active.
// A no-op when dirs.ESP is unset (tests, or a device with no separate ESP path).
func SyncBootState(walPath string, dirs StageDirs) error {
	if dirs.ESP == "" {
		return nil
	}
	d, err := deployment.Load(walPath)
	if err != nil {
		return err
	}
	b := BootState{Target: "active"}
	switch {
	case d.NeedsRecovery():
		// A candidate spent its whole trial budget with no good slot to fall back
		// to: arm the loader to boot the always-present recovery slot instead of
		// looping on a dead main.
		b = BootState{Target: "recovery"}
	case d.HasPending():
		b = BootState{Target: "next", Trial: true, Attempts: d.RootFS.BootAttempts}
	}
	return WriteBootState(filepath.Join(dirs.ESP, "boot-state"), b)
}

// BootState is the minimal slot-selection state on the ESP (/EFI/atom/boot-state):
// the daemon writes it, the Zig loader reads (and decrements attempts) pre-boot.
// Line-based key=value by contract so the loader parses it without a JSON lib.
type BootState struct {
	Target   string // "active", "next", or "recovery": which kernelcache slot to boot
	Trial    bool   // a candidate trial is in progress
	Attempts int    // remaining trial boots (loader decrements; 0 -> fall back to active)
}

// Marshal renders the boot-state file exactly as the loader expects.
func (b BootState) Marshal() string {
	trial := 0
	if b.Trial {
		trial = 1
	}
	return fmt.Sprintf("target=%s\ntrial=%d\nattempts=%d\n", b.Target, trial, b.Attempts)
}

// WriteBootState writes the ESP boot-state crash-durably: a unique temp is
// written, fsync'd, atomically renamed, and the ESP directory is fsync'd. This is the
// single file that decides which slot boots; on the FAT ESP an unflushed/torn write on
// power loss would leave the loader defaulting to 'active' (boot loop / recovery not
// armed). The unique temp name also avoids the collision of a fixed ".tmp".
func WriteBootState(path string, b BootState) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if _, err := tmp.Write([]byte(b.Marshal())); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, derr := os.Open(dir); derr == nil { // best-effort dir fsync (FAT may not support it)
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// ReadBootState parses the ESP boot-state (the same fields the loader reads).
func ReadBootState(path string) (BootState, error) {
	f, err := os.Open(path)
	if err != nil {
		return BootState{}, err
	}
	defer f.Close()
	var b BootState
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch k {
		case "target":
			b.Target = v
		case "trial":
			b.Trial = v == "1"
		case "attempts":
			b.Attempts, _ = strconv.Atoi(v)
		}
	}
	return b, sc.Err()
}

// slotGroup is a set of files that only mean anything together: an image and the
// material that proves it. Promoting one without the other is what bricks a device.
type slotGroup struct {
	dir      string
	prefix   string
	suffixes []string
}

// PromoteSlots canonicalizes the on-disk slots after a candidate is promoted: the
// -next artifacts become -active and the old -active becomes -prev (kept for
// rollback), for both the kernelcache (ESP) and the rootfs. A group with nothing
// staged is skipped (a WAL-only deploy is a no-op).
//
// Each group moves ALL-OR-NOTHING. A rootfs image is only bootable together with the
// verity hash tree it was measured into, and a kernelcache only with the signature
// the loader checks it against: renaming the image while leaving the old hash tree or
// the old signature in place produces a system that fails verity or fails to chain --
// a brick, on the reboot the user asked for. So a partially staged group is refused
// before anything moves, and the device keeps booting what it has.
func PromoteSlots(dirs StageDirs) error {
	groups := []slotGroup{
		{dirs.ESP, "kernelcache", []string{".efi", ".efi.sig"}},
		{dirs.Rootfs, "rootfs", []string{".erofs", ".hash"}},
	}
	for _, g := range groups {
		staged, missing := 0, []string(nil)
		for _, s := range g.suffixes {
			if _, err := os.Stat(filepath.Join(g.dir, g.prefix+"-next"+s)); err == nil {
				staged++
			} else {
				missing = append(missing, g.prefix+"-next"+s)
			}
		}
		if staged == 0 {
			continue // nothing staged for this group
		}
		if len(missing) > 0 {
			return fmt.Errorf("promote: %s partially staged, missing %v -- refusing (would not boot)",
				g.prefix, missing)
		}
		for _, s := range g.suffixes {
			next := filepath.Join(g.dir, g.prefix+"-next"+s)
			active := filepath.Join(g.dir, g.prefix+"-active"+s)
			prev := filepath.Join(g.dir, g.prefix+"-prev"+s)
			if _, err := os.Stat(active); err == nil {
				if err := os.Rename(active, prev); err != nil {
					return fmt.Errorf("promote: %s%s active->prev: %w", g.prefix, s, err)
				}
			}
			if err := os.Rename(next, active); err != nil {
				return fmt.Errorf("promote: %s%s next->active: %w", g.prefix, s, err)
			}
		}
	}
	return nil
}
