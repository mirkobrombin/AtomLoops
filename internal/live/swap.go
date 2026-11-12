// Package live swaps the running root for a staged, verified one without a
// reboot. It only moves mounts: the root filesystem is replaced under every
// process of the init mount namespace, while /var, /run, /dev, /proc, /sys,
// /home, /boot and every other mount carry over untouched. Which updates may
// be applied this way, and what restarts afterwards, is decided by the system
// through the apply class of the release and its hooks, never here.
package live

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/mirkobrombin/atomloops/boot"
)

// Anchor is an empty directory every live-capable image ships. The new root
// is prepared under it, and the old root is parked on it after the switch.
const Anchor = "/usr/lib/atomloops/live"

// Config describes the root to switch to.
type Config struct {
	Image     string
	HashTree  string
	RootHash  string
	Name      string
	Anchor    string
	EtcUpper  string
	EtcWork   string
	Mountinfo string
}

func (c *Config) defaults() {
	if c.Anchor == "" {
		c.Anchor = Anchor
	}
	if c.EtcUpper == "" {
		c.EtcUpper = "/var/etc-upper"
	}
	if c.EtcWork == "" {
		c.EtcWork = "/var/etc-work"
	}
	if c.Mountinfo == "" {
		c.Mountinfo = "/proc/self/mountinfo"
	}
	if c.Name == "" {
		h := c.RootHash
		if len(h) > 12 {
			h = h[:12]
		}
		c.Name = "vroot-" + h
	}
}

type mountEntry struct {
	id, parent int
	dev        string
	point      string
	fstype     string
	source     string
	super      string
	shared     bool
}

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func readMounts(path string) ([]mountEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []mountEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		left, right, ok := strings.Cut(sc.Text(), " - ")
		if !ok {
			continue
		}
		lf, rf := strings.Fields(left), strings.Fields(right)
		if len(lf) < 6 || len(rf) < 2 {
			continue
		}
		e := mountEntry{dev: lf[2], point: unescape(lf[4]), fstype: rf[0], source: unescape(rf[1])}
		e.id, _ = strconv.Atoi(lf[0])
		e.parent, _ = strconv.Atoi(lf[1])
		if len(rf) > 2 {
			e.super = rf[2]
		}
		for _, opt := range lf[6:] {
			if strings.HasPrefix(opt, "shared:") {
				e.shared = true
			}
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

func topAt(mounts []mountEntry, point string, parent int) (mountEntry, bool) {
	var found mountEntry
	ok := false
	for _, m := range mounts {
		if m.point == point && (parent < 0 || m.parent == parent) {
			found, ok = m, true
		}
	}
	return found, ok
}

func childrenOf(mounts []mountEntry, id int) []mountEntry {
	var out []mountEntry
	for _, m := range mounts {
		if m.parent == id && m.id != id {
			out = append(out, m)
		}
	}
	return out
}

func superOption(super, key string) string {
	for _, o := range strings.Split(super, ",") {
		if v, ok := strings.CutPrefix(o, key+"="); ok {
			return v
		}
	}
	return ""
}

// Swap is a switched root that is still on trial: Rollback returns to the old
// root, Commit lets the old root go.
type Swap struct {
	c         Config
	staging   string
	newRoot   string
	oldShared bool
	oldRoot   mountEntry
	loops     []string
	mapped    bool
	mounted   bool
	etcNew    bool
	moved     []string
	etcMoved  []string
	pivoted   bool
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func mountFlags(target string, flags uintptr) error {
	if err := syscall.Mount("", target, "", flags, ""); err != nil {
		return fmt.Errorf("live: propagation of %s: %w", target, err)
	}
	return nil
}

func move(src, dst string) error {
	if err := syscall.Mount(src, dst, "", syscall.MS_MOVE, ""); err != nil {
		return fmt.Errorf("live: move %s to %s: %w", src, dst, err)
	}
	return nil
}

func kernelRelease() string {
	var u syscall.Utsname
	if syscall.Uname(&u) != nil {
		return ""
	}
	b := make([]byte, 0, len(u.Release))
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func modulesFor(root, release string) (string, bool) {
	for _, d := range []string{"/usr/lib/modules/", "/lib/modules/"} {
		if exists(root + d + release) {
			return d + release, true
		}
	}
	return "", false
}

// Switch mounts the new root and makes it the root of every process of the
// init mount namespace. On error nothing has changed.
func Switch(c Config) (s *Swap, err error) {
	c.defaults()
	if !boot.ValidRootHash(c.RootHash) {
		return nil, errors.New("live: invalid root hash")
	}
	if !exists(c.Anchor) {
		return nil, fmt.Errorf("live: the running root has no %s", c.Anchor)
	}
	mounts, err := readMounts(c.Mountinfo)
	if err != nil {
		return nil, err
	}
	root, ok := topAt(mounts, "/", -1)
	if !ok {
		return nil, errors.New("live: no root mount")
	}
	if root.fstype != "erofs" {
		return nil, fmt.Errorf("live: the root is %s, not a verified image", root.fstype)
	}
	s = &Swap{c: c, oldShared: root.shared, oldRoot: root, staging: c.Anchor, newRoot: c.Anchor + "/new"}
	defer func() {
		if err != nil {
			if uerr := s.undo(); uerr != nil {
				err = fmt.Errorf("%w (and undoing it: %v)", err, uerr)
			}
			s = nil
		}
	}()
	if err = mountFlags("/", syscall.MS_PRIVATE); err != nil {
		return
	}
	if err = syscall.Mount("tmpfs", s.staging, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=0700"); err != nil {
		err = fmt.Errorf("live: staging mount: %w", err)
		return
	}
	s.mounted = true
	if err = mountFlags(s.staging, syscall.MS_PRIVATE); err != nil {
		return
	}
	if err = os.Mkdir(s.newRoot, 0o700); err != nil {
		return
	}
	dl, err := boot.AttachLoop(c.Image)
	if err != nil {
		return
	}
	s.loops = append(s.loops, dl)
	hl, err := boot.AttachLoop(c.HashTree)
	if err != nil {
		return
	}
	s.loops = append(s.loops, hl)
	node, err := boot.OpenVerity(c.Name, dl, hl, c.RootHash)
	if err != nil {
		return
	}
	s.mapped = true
	if !boot.HasEROFS(node) {
		err = errors.New("live: the new root does not verify against its signed root hash")
		return
	}
	if err = syscall.Mount(node, s.newRoot, "erofs", syscall.MS_RDONLY, ""); err != nil {
		err = fmt.Errorf("live: mount the new root: %w", err)
		return
	}
	if err = mountFlags(s.newRoot, syscall.MS_PRIVATE); err != nil {
		return
	}
	if !exists(s.newRoot + c.Anchor) {
		err = fmt.Errorf("live: the new root has no %s", c.Anchor)
		return
	}
	if rel := kernelRelease(); rel != "" {
		if _, had := modulesFor("", rel); had {
			if _, has := modulesFor(s.newRoot, rel); !has {
				err = fmt.Errorf("live: the new root has no modules for the running kernel %s", rel)
				return
			}
		}
	}

	etc, hasEtc := topAt(mounts, "/etc", root.id)
	var top []mountEntry
	for _, m := range childrenOf(mounts, root.id) {
		if m.point == c.Anchor || (hasEtc && m.id == etc.id) {
			continue
		}
		top = append(top, m)
	}
	var etcKids []mountEntry
	if hasEtc {
		if etc.fstype != "overlay" {
			err = fmt.Errorf("live: /etc is %s, expected an overlay", etc.fstype)
			return
		}
		etcKids = childrenOf(mounts, etc.id)
	}
	for _, m := range top {
		if !exists(s.newRoot + m.point) {
			err = fmt.Errorf("live: the new root has no %s to carry the mount over", m.point)
			return
		}
	}

	if hasEtc {
		work := c.EtcWork + "-live"
		if strings.HasSuffix(superOption(etc.super, "workdir"), "-live") {
			work = c.EtcWork
		}
		if err = os.MkdirAll(work, 0o755); err != nil {
			return
		}
		opts := "lowerdir=" + s.newRoot + "/etc,upperdir=" + c.EtcUpper + ",workdir=" + work
		if err = syscall.Mount("overlay", s.newRoot+"/etc", "overlay", 0, opts); err != nil {
			err = fmt.Errorf("live: mount the new /etc: %w", err)
			return
		}
		s.etcNew = true
		for _, m := range etcKids {
			if !exists(s.newRoot + m.point) {
				err = fmt.Errorf("live: the new /etc has no %s to carry the mount over", m.point)
				return
			}
		}
	}

	sort.SliceStable(top, func(i, j int) bool { return top[i].id < top[j].id })
	for _, m := range top {
		if err = move(m.point, s.newRoot+m.point); err != nil {
			return
		}
		s.moved = append(s.moved, m.point)
	}
	for _, m := range etcKids {
		if err = move(m.point, s.newRoot+m.point); err != nil {
			return
		}
		s.etcMoved = append(s.etcMoved, m.point)
	}

	if err = syscall.PivotRoot(s.newRoot, s.newRoot+c.Anchor); err != nil {
		err = fmt.Errorf("live: pivot_root: %w", err)
		return
	}
	s.pivoted = true
	if err = os.Chdir("/"); err != nil {
		return
	}
	if s.oldShared {
		if err = mountFlags("/", syscall.MS_SHARED); err != nil {
			return
		}
	}
	return s, nil
}

// OldRoot is where the previous root is reachable while the swap is on trial.
func (s *Swap) OldRoot() string { return s.c.Anchor }

// Rollback returns every process to the previous root.
func (s *Swap) Rollback() error { return s.undo() }

func (s *Swap) undo() error {
	var errs []error
	if s.pivoted {
		old := s.c.Anchor
		if err := mountFlags("/", syscall.MS_PRIVATE); err != nil {
			return err
		}
		for i := len(s.etcMoved) - 1; i >= 0; i-- {
			if err := move(s.etcMoved[i], old+s.etcMoved[i]); err != nil {
				return err
			}
		}
		s.etcMoved = nil
		for i := len(s.moved) - 1; i >= 0; i-- {
			if err := move(s.moved[i], old+s.moved[i]); err != nil {
				return err
			}
		}
		s.moved = nil
		if err := syscall.PivotRoot(old, old+s.staging+"/new"); err != nil {
			return fmt.Errorf("live: pivot back: %w", err)
		}
		s.pivoted = false
		os.Chdir("/")
	}
	for i := len(s.etcMoved) - 1; i >= 0; i-- {
		if err := move(s.newRoot+s.etcMoved[i], s.etcMoved[i]); err != nil {
			return err
		}
	}
	s.etcMoved = nil
	for i := len(s.moved) - 1; i >= 0; i-- {
		if err := move(s.newRoot+s.moved[i], s.moved[i]); err != nil {
			return err
		}
	}
	s.moved = nil
	if s.mounted {
		if err := syscall.Unmount(s.staging, syscall.MNT_DETACH); err != nil {
			errs = append(errs, fmt.Errorf("live: release the staging mount: %w", err))
		}
		s.mounted = false
	}
	if s.mapped {
		if err := boot.CloseVerityDeferred(s.c.Name); err != nil {
			errs = append(errs, err)
		}
		s.mapped = false
	}
	for _, l := range s.loops {
		if err := boot.AutoclearLoop(l); err != nil {
			boot.DetachLoop(l)
		}
	}
	s.loops = nil
	if s.oldShared {
		if err := mountFlags("/", syscall.MS_SHARED); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Commit lets the previous root go. Processes still running from it keep it
// alive; its verity mapping and loop devices are released with the last of
// them.
func (s *Swap) Commit() error {
	if !s.pivoted {
		return errors.New("live: nothing to commit")
	}
	if err := syscall.Unmount(s.c.Anchor, syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("live: release the previous root: %w", err)
	}
	s.pivoted = false
	releaseDevice(s.oldRoot.dev)
	for _, l := range s.loops {
		boot.AutoclearLoop(l)
	}
	return nil
}

func releaseDevice(majmin string) {
	sys := filepath.Join("/sys/dev/block", majmin)
	if b, err := os.ReadFile(filepath.Join(sys, "dm", "name")); err == nil {
		slaves, _ := os.ReadDir(filepath.Join(sys, "slaves"))
		boot.CloseVerityDeferred(strings.TrimSpace(string(b)))
		for _, sl := range slaves {
			if strings.HasPrefix(sl.Name(), "loop") {
				boot.AutoclearLoop("/dev/" + sl.Name())
			}
		}
		return
	}
	if strings.HasPrefix(filepath.Base(mustReadlink(sys)), "loop") {
		boot.AutoclearLoop("/dev/" + filepath.Base(mustReadlink(sys)))
	}
}

func mustReadlink(p string) string {
	t, err := os.Readlink(p)
	if err != nil {
		return ""
	}
	return t
}
