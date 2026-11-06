package boot

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// DiskHealth is what an NVMe controller reports about itself in its SMART log.
type DiskHealth struct {
	Dev              string
	CriticalWarning  uint8
	TemperatureK     uint16
	SpareLeft        uint8
	PercentUsed      uint8
	MediaErrors      uint64
	ErrorLogEntries  uint64
	UnsafeShutdowns  uint64
	PowerOnHours     uint64
	ReadErrorUnknown bool
}

// Failing reports a controller that says its media or itself cannot be
// trusted: a critical warning or media errors.
func (h DiskHealth) Failing() bool {
	return h.CriticalWarning != 0 || h.MediaErrors > 0
}

func (h DiskHealth) String() string {
	if h.ReadErrorUnknown {
		return h.Dev + ": SMART log unavailable"
	}
	return fmt.Sprintf("%s: critical_warning=0x%02x media_errors=%d error_log=%d unsafe_shutdowns=%d used=%d%% spare=%d%% temp=%dC power_on_hours=%d",
		h.Dev, h.CriticalWarning, h.MediaErrors, h.ErrorLogEntries, h.UnsafeShutdowns, h.PercentUsed, h.SpareLeft, int(h.TemperatureK)-273, h.PowerOnHours)
}

// ParseNVMeSMART decodes the 512-byte SMART / Health Information log page.
func ParseNVMeSMART(dev string, b []byte) DiskHealth {
	if len(b) < 512 {
		return DiskHealth{Dev: dev, ReadErrorUnknown: true}
	}
	le := binary.LittleEndian
	return DiskHealth{
		Dev:             dev,
		CriticalWarning: b[0],
		TemperatureK:    le.Uint16(b[1:]),
		SpareLeft:       b[3],
		PercentUsed:     b[5],
		PowerOnHours:    le.Uint64(b[128:]),
		UnsafeShutdowns: le.Uint64(b[144:]),
		MediaErrors:     le.Uint64(b[160:]),
		ErrorLogEntries: le.Uint64(b[176:]),
	}
}

type nvmeAdminCmd struct {
	Opcode      uint8
	Flags       uint8
	Rsvd1       uint16
	Nsid        uint32
	Cdw2        uint32
	Cdw3        uint32
	Metadata    uint64
	Addr        uint64
	MetadataLen uint32
	DataLen     uint32
	Cdw10       uint32
	Cdw11       uint32
	Cdw12       uint32
	Cdw13       uint32
	Cdw14       uint32
	Cdw15       uint32
	TimeoutMs   uint32
	Result      uint32
}

const nvmeIoctlAdminCmd = 0xC0484E41

func readNVMeSMART(path string) DiskHealth {
	dev := filepath.Base(path)
	f, err := os.Open(path)
	if err != nil {
		return DiskHealth{Dev: dev, ReadErrorUnknown: true}
	}
	defer f.Close()
	buf := make([]byte, 512)
	cmd := nvmeAdminCmd{
		Opcode:    0x02,
		Nsid:      0xffffffff,
		Addr:      uint64(uintptr(unsafe.Pointer(&buf[0]))),
		DataLen:   uint32(len(buf)),
		Cdw10:     uint32(len(buf)/4-1)<<16 | 0x02,
		TimeoutMs: 2000,
	}
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), nvmeIoctlAdminCmd, uintptr(unsafe.Pointer(&cmd))); e != 0 {
		return DiskHealth{Dev: dev, ReadErrorUnknown: true}
	}
	return ParseNVMeSMART(dev, buf)
}

// DisksHealth reads the SMART log of every NVMe controller.
func DisksHealth() []DiskHealth {
	var out []DiskHealth
	ctrls, _ := filepath.Glob("/dev/nvme[0-9]*")
	for _, c := range ctrls {
		if strings.Contains(filepath.Base(c)[4:], "n") {
			continue
		}
		out = append(out, readNVMeSMART(c))
	}
	return out
}

func onController(dev, ctrl string) bool {
	return strings.HasPrefix(filepath.Base(dev), ctrl+"n")
}
