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

// WriteBootState writes the ESP boot-state atomically (temp + rename).
func WriteBootState(path string, b BootState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.Marshal()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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

// PromoteSlots canonicalizes the on-disk slots after a candidate is promoted: the
// -next artifacts become -active and the old -active becomes -prev (kept for
// rollback), for both the kernelcache (ESP) and the rootfs. Missing -next files
// are skipped (a WAL-only deploy with no staged artifacts is a no-op).
func PromoteSlots(dirs StageDirs) error {
	moves := []struct{ dir, prefix, suffix string }{
		{dirs.ESP, "kernelcache", ".efi"},
		{dirs.Rootfs, "rootfs", ".erofs"},
	}
	for _, m := range moves {
		next := filepath.Join(m.dir, m.prefix+"-next"+m.suffix)
		active := filepath.Join(m.dir, m.prefix+"-active"+m.suffix)
		prev := filepath.Join(m.dir, m.prefix+"-prev"+m.suffix)
		if _, err := os.Stat(next); err != nil {
			continue // nothing staged for this artifact
		}
		if _, err := os.Stat(active); err == nil {
			if err := os.Rename(active, prev); err != nil {
				return fmt.Errorf("promote: %s active->prev: %w", m.prefix, err)
			}
		}
		if err := os.Rename(next, active); err != nil {
			return fmt.Errorf("promote: %s next->active: %w", m.prefix, err)
		}
	}
	return nil
}
