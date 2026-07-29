package otad

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

// SyncBootState writes the ESP boot-state to match the WAL: a pending candidate
// means boot the -next slot on its remaining boot budget; otherwise boot -active.
// A no-op when dirs.ESP is unset (tests, or a device with no separate ESP path).
func SyncBootState(walPath string, dirs StageDirs) error {
	d, err := deployment.Load(walPath)
	if err != nil {
		return err
	}
	return writeDeploymentBootState(d, dirs)
}

func writeDeploymentBootState(d *deployment.Deployment, dirs StageDirs) error {
	if dirs.ESP == "" {
		return nil
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

func nonEmpty(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Size() > 0
}

func sameFileContent(a, b string) bool {
	aa, err := os.Open(a)
	if err != nil {
		return false
	}
	defer aa.Close()
	bb, err := os.Open(b)
	if err != nil {
		return false
	}
	defer bb.Close()
	as, err := aa.Stat()
	if err != nil {
		return false
	}
	bs, err := bb.Stat()
	if err != nil || as.Size() != bs.Size() {
		return false
	}
	ah := sha256.New()
	bh := sha256.New()
	if _, err := io.Copy(ah, aa); err != nil {
		return false
	}
	if _, err := io.Copy(bh, bb); err != nil {
		return false
	}
	return string(ah.Sum(nil)) == string(bh.Sum(nil))
}

func sameFileIdentity(a, b string) bool {
	aa, err := os.Stat(a)
	if err != nil {
		return false
	}
	bb, err := os.Stat(b)
	return err == nil && os.SameFile(aa, bb)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil &&
		!errors.Is(err, syscall.EINVAL) &&
		!errors.Is(err, syscall.ENOTSUP) {
		return err
	}
	return nil
}

func copyFileSync(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	dir := filepath.Dir(dst)
	out, err := os.CreateTemp(dir, "."+filepath.Base(dst)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := out.Name()
	defer os.Remove(tmp)
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	return syncDir(dir)
}

func linkFileSync(src, dst string) error {
	dir := filepath.Dir(dst)
	reservation, err := os.CreateTemp(dir, "."+filepath.Base(dst)+".link-*")
	if err != nil {
		return err
	}
	tmp := reservation.Name()
	if err := reservation.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Remove(tmp); err != nil {
		return err
	}
	if err := os.Link(src, tmp); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	return syncDir(dir)
}

func preflightSlots(groups []slotGroup) error {
	for _, g := range groups {
		if g.dir == "" {
			continue
		}
		staged := 0
		for _, s := range g.suffixes {
			if nonEmpty(filepath.Join(g.dir, g.prefix+"-next"+s)) {
				staged++
			}
		}
		if staged == 0 {
			return fmt.Errorf("promote: %s candidate is missing", g.prefix)
		}
		for _, s := range g.suffixes {
			next := filepath.Join(g.dir, g.prefix+"-next"+s)
			active := filepath.Join(g.dir, g.prefix+"-active"+s)
			if nonEmpty(next) {
				if !nonEmpty(active) {
					return fmt.Errorf("promote: %s%s has no active slot", g.prefix, s)
				}
				continue
			}
			return fmt.Errorf("promote: %s partially staged, missing %s", g.prefix, filepath.Base(next))
		}
	}
	return nil
}

// PromoteSlots prepares the active and previous slots while the loader still points
// at -next. The ESP keeps its -next pair until the WAL and boot-state are durable, so
// a crash during promotion can still boot the verified candidate and retry.
func PromoteSlots(dirs StageDirs) error {
	groups := []slotGroup{
		{dirs.Rootfs, "rootfs", []string{".erofs", ".hash"}},
		{dirs.ESP, "kernelcache", []string{".efi", ".efi.sig"}},
	}
	if err := preflightSlots(groups); err != nil {
		return err
	}
	for _, g := range groups {
		for _, s := range g.suffixes {
			next := filepath.Join(g.dir, g.prefix+"-next"+s)
			active := filepath.Join(g.dir, g.prefix+"-active"+s)
			prev := filepath.Join(g.dir, g.prefix+"-prev"+s)
			if !nonEmpty(next) {
				continue
			}
			if g.prefix == "kernelcache" {
				if sameFileContent(active, next) {
					continue
				}
				if err := copyFileSync(active, prev); err != nil {
					return fmt.Errorf("promote: %s%s active->prev: %w", g.prefix, s, err)
				}
				if err := copyFileSync(next, active); err != nil {
					return fmt.Errorf("promote: %s%s next->active: %w", g.prefix, s, err)
				}
				continue
			}
			if sameFileIdentity(active, next) {
				continue
			}
			if err := linkFileSync(active, prev); err != nil {
				return fmt.Errorf("promote: %s%s active->prev: %w", g.prefix, s, err)
			}
			if err := linkFileSync(next, active); err != nil {
				return fmt.Errorf("promote: %s%s next->active: %w", g.prefix, s, err)
			}
		}
	}
	return nil
}

// CleanupNextSlots runs only after promotion is committed. Failure is harmless:
// the loader points at -active and a later stage replaces the stale files.
func CleanupNextSlots(dirs StageDirs) {
	if dirs.ESP != "" {
		for _, s := range []string{".efi", ".efi.sig"} {
			_ = os.Remove(filepath.Join(dirs.ESP, "kernelcache-next"+s))
		}
	}
	if dirs.Rootfs != "" {
		for _, s := range []string{".erofs", ".hash"} {
			_ = os.Remove(filepath.Join(dirs.Rootfs, "rootfs-next"+s))
		}
	}
}
