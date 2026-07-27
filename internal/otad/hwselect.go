package otad

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DetectGPUChips scans PCI display-class devices under sysfsRoot ("" means /sys) and
// returns the GPU add-on "chips" this machine actually has: "nvidia" (PCI vendor
// 0x10de) and/or "amd" (0x1002). Intel and everything else are covered by the base
// image, so they are not returned. Done natively (no lspci, no shell) so the update
// tool stays a single fast binary.
func DetectGPUChips(sysfsRoot string) []string {
	if sysfsRoot == "" {
		sysfsRoot = "/sys"
	}
	var nvidia, amd bool
	devs, _ := filepath.Glob(filepath.Join(sysfsRoot, "bus", "pci", "devices", "*"))
	for _, d := range devs {
		cls, err := os.ReadFile(filepath.Join(d, "class"))
		if err != nil || !strings.HasPrefix(strings.TrimSpace(string(cls)), "0x03") {
			continue // PCI class 0x03xxxx = display controller
		}
		ven, err := os.ReadFile(filepath.Join(d, "vendor"))
		if err != nil {
			continue
		}
		switch strings.TrimSpace(string(ven)) {
		case "0x10de":
			nvidia = true
		case "0x1002":
			amd = true
		}
	}
	out := make([]string, 0, 2)
	if nvidia {
		out = append(out, "nvidia")
	}
	if amd {
		out = append(out, "amd")
	}
	return out
}

// RunningKernel returns the running kernel release (uname -r), read from
// /proc/sys/kernel/osrelease. Empty on failure.
func RunningKernel() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// MatchesHardware reports whether this bundle should be staged on a machine with the
// given detected GPU chips and running kernel. A bundle that names Chips applies only
// if at least one of them is present; a bundle with a kernel bound applies only if the
// running kernel is within [KernelMin, KernelMax] (an empty bound is unbounded). A
// kernel-bound driver bundle pins KernelMin==KernelMax to the exact kernel it was
// built against, so it is staged only for that kernel.
func (f FirmwareBundleSpec) MatchesHardware(chips []string, kernel string) bool {
	// GPU-presence gate: a bundle that names a GPU add-on chip (one DetectGPUChips can
	// report) is staged only when that GPU is present. Chip names outside that
	// vocabulary (e.g. a wifi firmware bundle) are base/survival firmware, not GPU
	// add-ons, so they are not GPU-gated here and stage regardless.
	var need []string
	for _, c := range f.Chips {
		if isGPUChip(c) {
			need = append(need, c)
		}
	}
	if len(need) > 0 {
		hit := false
		for _, c := range need {
			for _, d := range chips {
				if c == d {
					hit = true
				}
			}
		}
		if !hit {
			return false
		}
	}
	if f.KernelMin != "" && kernel != "" && cmpKernel(kernel, f.KernelMin) < 0 {
		return false
	}
	if f.KernelMax != "" && kernel != "" && cmpKernel(kernel, f.KernelMax) > 0 {
		return false
	}
	return true
}

// isGPUChip reports whether c is a GPU add-on chip the detector can report
// (DetectGPUChips returns exactly these). Only these gate a bundle on GPU presence.
func isGPUChip(c string) bool { return c == "nvidia" || c == "amd" }

// cmpKernel compares two kernel version strings by dotted/dashed numeric parts
// (e.g. "7.1.3"). Returns -1, 0, or 1. Parts that are not integers compare lexically.
func cmpKernel(a, b string) int {
	as, bs := splitVer(a), splitVer(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var x, y string
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		xi, xe := strconv.Atoi(x)
		yi, ye := strconv.Atoi(y)
		if xe == nil && ye == nil {
			if xi != yi {
				if xi < yi {
					return -1
				}
				return 1
			}
			continue
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func splitVer(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' || r == '_' })
}

// isKernelBoundFor reports whether this is a kernel-bound driver bundle (it pins a
// kernel bound) that covers the given GPU chip. Firmware-only bundles (no kernel
// bound) are not driver bundles and never gate a kernel change.
func (f FirmwareBundleSpec) isKernelBoundFor(chip string) bool {
	if f.KernelMin == "" && f.KernelMax == "" {
		return false
	}
	for _, c := range f.Chips {
		if c == chip {
			return true
		}
	}
	return false
}

// CoupledKernelCheck refuses a kernel-changing update that would strand a kernel-bound
// GPU driver bundle. When the manifest declares a target kernel (KernelRelease) that
// differs from the running one, then for every present GPU chip the manifest offers a
// kernel-bound driver bundle for, it must also offer one matching the target kernel;
// otherwise the update is refused so the machine never boots the new kernel with a dead
// GPU driver. chips is this machine's detected GPU set (DetectGPUChips). A manifest with
// no KernelRelease, or one that does not change the kernel, is never gated.
func (m Manifest) CoupledKernelCheck(chips []string) error {
	target := m.KernelRelease
	if target == "" || target == RunningKernel() {
		return nil
	}
	bundles := m.FirmwareBundleList()
	for _, chip := range chips {
		offers, matches := false, false
		for _, b := range bundles {
			if !b.isKernelBoundFor(chip) {
				continue
			}
			offers = true
			if b.MatchesHardware([]string{chip}, target) {
				matches = true
			}
		}
		if offers && !matches {
			return fmt.Errorf("coupled-kernel: update targets kernel %s but ships no %s driver bundle for it; refusing to strand the GPU", target, chip)
		}
	}
	return nil
}
