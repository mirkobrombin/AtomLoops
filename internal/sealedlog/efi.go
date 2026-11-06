package sealedlog

import (
	"encoding/binary"
)

// VendorGUID is the EFI variable namespace shared by the loader, the kernels
// that log through firmware and the collector.
const VendorGUID = "6a1c5e1d-5b8e-4c2f-9d4e-5349584f5301"

// EFI variables of the sealed log.
const (
	// VarBoot is volatile and set by the loader: u32 boot number, u64 sequence
	// of the block the loader wrote for it.
	VarBoot = "SintyLogBoot"
	// VarEarly is non-volatile and written by a kernel that cannot reach the
	// ring: u32 boot number, then a payload. The collector seals and clears it.
	VarEarly = "SintyLogEarly"
	// VarEarlyPrev is where a kernel moves VarEarly of an earlier boot that
	// nobody collected before it starts its own.
	VarEarlyPrev = "SintyLogPrev"
	// VarInit is non-volatile and written by the initramfs, in the VarEarly
	// format, with what it found and did before the root was mounted. It
	// outlives a boot that ends in recovery.
	VarInit = "SintyLogInit"
)

// LoaderBoot is what the loader told the running system through VarBoot.
type LoaderBoot struct {
	Boot uint32
	Seq  uint64
}

// ReadLoaderBoot reads VarBoot, ok false when the loader did not log.
func ReadLoaderBoot() (LoaderBoot, bool) {
	b, err := ReadEFIVar(VarBoot)
	if err != nil || len(b) < 12 {
		return LoaderBoot{}, false
	}
	return LoaderBoot{Boot: binary.LittleEndian.Uint32(b), Seq: binary.LittleEndian.Uint64(b[4:])}, true
}

// Early is a payload a kernel left in VarEarly.
type Early struct {
	Boot    uint32
	Payload Payload
}

// ParseEarly decodes the VarEarly data.
func ParseEarly(b []byte) (Early, error) {
	if len(b) < 5 {
		return Early{}, errShort
	}
	p, err := DecodePayload(b[4:])
	return Early{Boot: binary.LittleEndian.Uint32(b), Payload: p}, err
}
