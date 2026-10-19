package boot

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Config describes how a boot finds its root.
type Config struct {
	// RootHash is the dm-verity root hash from the signed kernel command line.
	RootHash string
	// Live boots a root that keeps no writable state on disk. Raw root and
	// hash partitions are accepted, as are the files of an optical medium.
	Live bool
	// Portable is a live boot of a removable root that may use an installed
	// data partition. Only partitions named PortableRoot and PortableHash
	// qualify.
	Portable     bool
	PortableRoot string
	PortableHash string
	// Unlocked marks a device whose owner turned verified boot off. The
	// signed root hash still picks the slot; the root is then mounted raw.
	Unlocked bool
	// DataMount and ISOMount are where the data partition and an optical
	// medium are mounted while the root is found.
	DataMount string
	ISOMount  string
	// Attempts and Interval bound the wait for slow boot media.
	Attempts int
	Interval time.Duration
}

func (c *Config) defaults() {
	if c.DataMount == "" {
		c.DataMount = "/sysdata"
	}
	if c.ISOMount == "" {
		c.ISOMount = "/isomedia"
	}
	if c.Attempts == 0 {
		c.Attempts = 75
	}
	if c.Interval == 0 {
		c.Interval = 200 * time.Millisecond
	}
	if c.Portable {
		c.Live = true
	}
}

// Ops is what root selection needs from the system. The defaults talk to the
// kernel; tests replace them.
type Ops struct {
	Partitions   func() []Partition
	MountData    func(dev, dir string) bool
	Unmount      func(dir string) error
	Glob         func(pattern string) []string
	Exists       func(path string) bool
	AttachLoop   func(file string) (string, error)
	DetachLoop   func(dev string) error
	OpenVerity   func(name, data, hash, rootHash string) (string, error)
	CloseVerity  func(name string) error
	HasEROFS     func(dev string) bool
	IsVerityHash func(dev string) bool
	HashRoot     func(dev string) (string, uint64)
	DevBytes     func(dev string) uint64
	MountISO     func(dev, dir string) bool
	DiskOf       func(dev string) string
	Sleep        func(time.Duration)
}

// SystemOps returns the Ops that act on the running kernel.
func SystemOps() Ops {
	return Ops{
		Partitions: Partitions,
		MountData: func(dev, dir string) bool {
			os.MkdirAll(dir, 0755)
			if syscall.Mount(dev, dir, "ext4", syscall.MS_RDONLY, "") == nil {
				return true
			}
			for _, flags := range []uintptr{0, syscall.MS_RDONLY} {
				if syscall.Mount(dev, dir, "f2fs", flags, "") == nil {
					return true
				}
			}
			return false
		},
		Unmount: func(dir string) error { return syscall.Unmount(dir, 0) },
		Glob: func(p string) []string {
			m, _ := filepath.Glob(p)
			return m
		},
		Exists: func(p string) bool {
			_, err := os.Stat(p)
			return err == nil
		},
		AttachLoop:  AttachLoop,
		DetachLoop:  DetachLoop,
		OpenVerity:  OpenVerity,
		CloseVerity: CloseVerity,
		HasEROFS:    HasEROFS,
		HashRoot: func(dev string) (string, uint64) {
			root, sb, err := VerityRootHash(dev)
			if err != nil {
				return "", 0
			}
			return root, sb.DataBlocks * uint64(sb.DataBlockSize)
		},
		DevBytes:     DevBytes,
		IsVerityHash: IsVerityHash,
		MountISO: func(dev, dir string) bool {
			os.MkdirAll(dir, 0755)
			return syscall.Mount(dev, dir, "iso9660", syscall.MS_RDONLY, "") == nil
		},
		DiskOf: DiskOf,
		Sleep:  time.Sleep,
	}
}

// Media is the boot media found so far: the Atom Loops data partition with
// its root slot files, and an optical medium.
type Media struct {
	DataDev    string
	SlotDatas  []string
	SlotHashes []string
	ISODev     string
	ISOData    string
	ISOHash    string
}

// FindData mounts the data partition read-only, the first partition that
// holds a root slot under boot/rootfs, and attaches every slot file to a
// read-only loop device.
func (m *Media) FindData(cfg *Config, ops Ops) {
	if m.DataDev != "" {
		return
	}
	for _, p := range ops.Partitions() {
		if strings.HasPrefix(filepath.Base(p.Dev), "sr") {
			continue
		}
		if !ops.MountData(p.Dev, cfg.DataMount) {
			continue
		}
		slots := ops.Glob(cfg.DataMount + "/boot/rootfs/rootfs-*.erofs")
		if len(slots) == 0 {
			ops.Unmount(cfg.DataMount)
			continue
		}
		m.DataDev = p.Dev
		Logf("data partition: %s", p.Dev)
		files := append(slots, ops.Glob(cfg.DataMount+"/boot/rootfs/rootfs-*.hash")...)
		for _, f := range files {
			loop, err := ops.AttachLoop(f)
			if err != nil {
				Logf("  %s: %v", f, err)
				continue
			}
			Logf("  %s -> %s", f, loop)
			if strings.HasSuffix(f, ".erofs") {
				m.SlotDatas = append(m.SlotDatas, loop)
			} else {
				m.SlotHashes = append(m.SlotHashes, loop)
			}
		}
		return
	}
}

// FindISO mounts an optical medium carrying live/rootfs.erofs and its hash,
// and attaches both files to loop devices.
func (m *Media) FindISO(cfg *Config, ops Ops) {
	if cfg.Portable || m.ISODev != "" {
		return
	}
	for _, p := range ops.Partitions() {
		if !strings.HasPrefix(filepath.Base(p.Dev), "sr") {
			continue
		}
		if !ops.MountISO(p.Dev, cfg.ISOMount) {
			continue
		}
		data, hash := cfg.ISOMount+"/live/rootfs.erofs", cfg.ISOMount+"/live/rootfs.hash"
		if ops.Exists(data) && ops.Exists(hash) {
			dl, err := ops.AttachLoop(data)
			if err == nil {
				hl, err := ops.AttachLoop(hash)
				if err == nil {
					m.ISODev, m.ISOData, m.ISOHash = p.Dev, dl, hl
					Logf("optical root: %s (%s %s)", p.Dev, dl, hl)
					return
				}
				ops.DetachLoop(dl)
			}
		}
		ops.Unmount(cfg.ISOMount)
	}
}

// Root is the root filesystem the boot settled on.
type Root struct {
	// Source is what to mount: the verity mapping, or the raw image of an
	// unlocked device.
	Source string
	Data   string
	Hash   string
	// Mapper names the verity mapping behind Source, empty when raw.
	Mapper  string
	Optical bool
	// FromSlot is set when the root is a slot file of the data partition.
	FromSlot bool
}

// RootMapper is the dm-verity mapping name of the verified root.
const RootMapper = "vroot"

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// SelectRoot finds the root image whose dm-verity tree matches the signed
// root hash. It retries while boot media come up. A locked device only ever
// gets a verity mapping back; an unlocked one gets the raw image of the slot
// the hash selects, or of the raw root when no slot matches.
func SelectRoot(cfg Config, m *Media, ops Ops) (*Root, error) {
	cfg.defaults()
	if !ValidRootHash(cfg.RootHash) {
		return nil, errors.New("no valid root hash on the kernel command line")
	}
	for i := 0; i < cfg.Attempts; i++ {
		m.FindData(&cfg, ops)
		m.FindISO(&cfg, ops)
		var root *Root
		if cfg.Unlocked {
			root = selectUnlocked(&cfg, m, ops)
		} else {
			root = selectVerified(&cfg, m, ops)
		}
		if root != nil {
			root.Optical = m.ISOData != "" && root.Data == m.ISOData
			root.FromSlot = contains(m.SlotDatas, root.Data)
			return root, nil
		}
		if i == 0 && m.DataDev == "" && m.ISODev == "" {
			Logf("waiting for boot media")
		}
		ops.Sleep(cfg.Interval)
	}
	return nil, errors.New("no root image matches the signed root hash")
}

func (cfg *Config) portablePart(p Partition, names ...string) bool {
	if !cfg.Portable {
		return true
	}
	return contains(names, p.PartName)
}

func selectVerified(cfg *Config, m *Media, ops Ops) *Root {
	var datas, hashes []string
	if cfg.Live {
		for _, p := range ops.Partitions() {
			if strings.HasPrefix(filepath.Base(p.Dev), "sr") && p.PartName == "" {
				continue
			}
			if !cfg.portablePart(p, cfg.PortableRoot, cfg.PortableHash) {
				continue
			}
			if ops.IsVerityHash(p.Dev) {
				hashes = append(hashes, p.Dev)
			} else if ops.HasEROFS(p.Dev) {
				datas = append(datas, p.Dev)
			}
		}
		if !cfg.Portable && m.ISOData != "" {
			datas = append(datas, m.ISOData)
			hashes = append(hashes, m.ISOHash)
		}
	} else {
		datas, hashes = m.SlotDatas, m.SlotHashes
	}
	for _, pair := range rankPairs(cfg, ops, datas, hashes) {
		d, h := pair[0], pair[1]
		if !samePairOrigin(m, ops, d, h) {
			continue
		}
		ops.CloseVerity(RootMapper)
		node, err := ops.OpenVerity(RootMapper, d, h, cfg.RootHash)
		if err != nil {
			continue
		}
		if ops.HasEROFS(node) {
			return &Root{Source: node, Data: d, Hash: h, Mapper: RootMapper}
		}
		ops.CloseVerity(RootMapper)
	}
	return nil
}

// rankPairs orders the data and hash pairs so the one the signed root hash
// names is mapped first. A trial boot keeps two slots side by side, and mapping
// the wrong pair first leaves a failed mapping that must be torn down before
// the right one can take its name. Pairs whose hash device names another root
// stay last, so an unreadable or unknown device is still tried.
func rankPairs(cfg *Config, ops Ops, datas, hashes []string) [][2]string {
	type ranked struct {
		pair  [2]string
		score int
	}
	var all []ranked
	for _, h := range hashes {
		root, want := "", uint64(0)
		if ops.HashRoot != nil {
			root, want = ops.HashRoot(h)
		}
		for _, d := range datas {
			score := 1
			switch {
			case root == "":
			case strings.EqualFold(root, cfg.RootHash):
				score = 3
			default:
				score = 0
			}
			if score > 0 && want > 0 && ops.DevBytes != nil && ops.DevBytes(d) == want {
				score++
			}
			all = append(all, ranked{[2]string{d, h}, score})
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].score > all[j].score })
	out := make([][2]string, len(all))
	for i, r := range all {
		out[i] = r.pair
	}
	return out
}

func samePairOrigin(m *Media, ops Ops, data, hash string) bool {
	if contains(m.SlotDatas, data) != contains(m.SlotHashes, hash) {
		return false
	}
	isoData := m.ISOData != "" && data == m.ISOData
	isoHash := m.ISOHash != "" && hash == m.ISOHash
	if isoData != isoHash {
		return false
	}
	if !contains(m.SlotDatas, data) && !isoData {
		return ops.DiskOf(data) == ops.DiskOf(hash)
	}
	return true
}

func selectUnlocked(cfg *Config, m *Media, ops Ops) *Root {
	if !cfg.Live && len(m.SlotHashes) > 0 {
		const probe = "vroot-select"
		for _, d := range m.SlotDatas {
			for _, h := range m.SlotHashes {
				ops.CloseVerity(probe)
				node, err := ops.OpenVerity(probe, d, h, cfg.RootHash)
				if err != nil {
					continue
				}
				ok := ops.HasEROFS(node)
				ops.CloseVerity(probe)
				if ok {
					Logf("unlocked: selected the root slot that matches the signed hash: %s", d)
					return &Root{Source: d, Data: d}
				}
			}
		}
	}
	var candidates []string
	if cfg.Live {
		if m.ISOData != "" {
			candidates = append(candidates, m.ISOData)
		}
		for _, p := range ops.Partitions() {
			if cfg.portablePart(p, cfg.PortableRoot) {
				candidates = append(candidates, p.Dev)
			}
		}
	} else {
		candidates = m.SlotDatas
	}
	for _, d := range candidates {
		if ops.HasEROFS(d) {
			return &Root{Source: d, Data: d}
		}
	}
	return nil
}

// ReleaseUnrelatedData lets go of a data partition the chosen root does not
// come from, so a live or portable root never adopts another installation's
// writable data by accident. A portable root keeps an installed data
// partition on purpose. It reports whether the data partition is still held.
func ReleaseUnrelatedData(cfg Config, m *Media, root *Root, ops Ops) (bool, error) {
	cfg.defaults()
	if m.DataDev == "" {
		return false, nil
	}
	if root.FromSlot {
		return true, nil
	}
	if cfg.Portable && ops.Exists(cfg.DataMount+"/.atom-var") {
		Logf("portable: raw root %s using installed data %s", root.Data, m.DataDev)
		return true, nil
	}
	for _, l := range append(append([]string{}, m.SlotDatas...), m.SlotHashes...) {
		ops.DetachLoop(l)
	}
	if err := ops.Unmount(cfg.DataMount); err != nil {
		return false, errors.New("cannot detach the unrelated data partition " + m.DataDev)
	}
	Logf("live: ignored unrelated data partition %s", m.DataDev)
	m.DataDev, m.SlotDatas, m.SlotHashes = "", nil, nil
	return false, nil
}
