package boot

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Diagnosis names why a boot could not reach its root, in terms a person and a
// support tool can both act on. Code is stable across releases.
type Diagnosis struct {
	Code   string
	Phase  string
	Cause  string
	Action string
	// RollbackHelps is false when the previous system lives on the same
	// partition that failed, so booting it cannot succeed either.
	RollbackHelps bool
}

// Facts is what the initramfs saw while looking for its root.
type Facts struct {
	Partitions []Partition
	Media      Media
	SlotFiles  []string
	HashFiles  []string
	HashMatch  bool
	KernelLog  string
	Disks      []DiskHealth
}

var ioError = regexp.MustCompile(`(?i)(I/O error, dev ([a-z0-9]+)|Buffer I/O error on dev(ice)? ([a-z0-9]+)|critical medium error, dev ([a-z0-9]+)|nvme ([a-z0-9]+): (I/O|controller is down|resetting controller))`)

func ioErrorDevices(log string) []string {
	var devs []string
	for _, m := range ioError.FindAllStringSubmatch(log, -1) {
		for _, d := range []string{m[2], m[4], m[5], m[6]} {
			if d != "" && !contains(devs, d) {
				devs = append(devs, d)
			}
		}
	}
	return devs
}

func sameDisk(dev, errDev string) bool {
	b := filepath.Base(dev)
	return b == errDev || strings.HasPrefix(b, errDev)
}

// Diagnose turns what the boot saw into one Diagnosis. The order matters: a
// failing disk explains an unmountable filesystem, and an unmountable
// filesystem explains missing images.
func Diagnose(f Facts) Diagnosis {
	data := f.Media.DataDev
	var candidates []string
	for _, u := range f.Media.Unmountable {
		candidates = append(candidates, u.Dev)
	}
	candidates = append(candidates, f.Media.Empty...)
	if data != "" {
		candidates = append(candidates, data)
	}
	for _, e := range ioErrorDevices(f.KernelLog) {
		for _, c := range candidates {
			if sameDisk(c, e) {
				return Diagnosis{
					Code:   "B02",
					Phase:  "storage",
					Cause:  "the disk holding the system reported read errors (" + e + ")",
					Action: "back up what can still be read, check the disk health, then reinstall from recovery",
				}
			}
		}
	}
	for _, h := range f.Disks {
		if !h.Failing() {
			continue
		}
		for _, c := range candidates {
			if onController(c, h.Dev) {
				return Diagnosis{
					Code:   "B02",
					Phase:  "storage",
					Cause:  fmt.Sprintf("the disk holding the system reports a failure (%s critical warning 0x%02x, %d media errors)", h.Dev, h.CriticalWarning, h.MediaErrors),
					Action: "back up what can still be read, check the disk health, then reinstall from recovery",
				}
			}
		}
	}
	if len(f.Media.Unmountable) > 0 && data == "" {
		return Diagnosis{
			Code:   "B03",
			Phase:  "data-mount",
			Cause:  "the data partition " + f.Media.Unmountable[0].Dev + " (" + f.Media.Unmountable[0].FS + ") cannot be mounted",
			Action: "check and repair the data partition from recovery",
		}
	}
	if data == "" && f.Media.ISODev == "" && len(f.Media.Empty) > 0 {
		return Diagnosis{
			Code:   "B04",
			Phase:  "root-image",
			Cause:  "the data partition " + f.Media.Empty[0] + " holds no system image",
			Action: "reinstall from recovery",
		}
	}
	if data == "" && f.Media.ISODev == "" {
		if len(f.Partitions) == 0 {
			return Diagnosis{
				Code:   "B01",
				Phase:  "storage",
				Cause:  "no storage device was found",
				Action: "check that the disk is detected by the firmware",
			}
		}
		return Diagnosis{
			Code:   "B01",
			Phase:  "storage",
			Cause:  "no partition holding a Sinty system was found",
			Action: "reinstall from recovery or from installation media",
		}
	}
	if data != "" && len(f.SlotFiles) == 0 {
		return Diagnosis{
			Code:   "B04",
			Phase:  "root-image",
			Cause:  "the data partition holds no system image",
			Action: "reinstall from recovery",
		}
	}
	if data != "" && len(f.HashFiles) == 0 {
		return Diagnosis{
			Code:   "B05",
			Phase:  "root-image",
			Cause:  "the system images have no verity hash tree",
			Action: "reinstall from recovery",
		}
	}
	if !f.HashMatch {
		return Diagnosis{
			Code:          "B06",
			Phase:         "verity",
			Cause:         "no system image matches the signed root hash of this boot",
			Action:        "start the previous system, or reinstall from recovery",
			RollbackHelps: true,
		}
	}
	return Diagnosis{
		Code:          "B07",
		Phase:         "verity",
		Cause:         "the system image matching the root hash fails verification",
		Action:        "start the previous system, or reinstall from recovery",
		RollbackHelps: true,
	}
}

// String renders the diagnosis as the first lines of a report.
func (d Diagnosis) String() string {
	return "code=" + d.Code + " phase=" + d.Phase + "\ncause: " + d.Cause + "\naction: " + d.Action + "\n"
}
