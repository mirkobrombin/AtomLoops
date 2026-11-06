package boot

import (
	"encoding/binary"
	"strconv"
	"time"

	"github.com/mirkobrombin/atomloops/internal/sealedlog"
)

const maxInitRecords = 32

// LogDiagnosis keeps the diagnosis in the sealed log. The record waits in an
// EFI variable until a booted system seals it, so it survives a boot that
// ends in recovery.
func LogDiagnosis(d Diagnosis) {
	n, _ := strconv.ParseUint(d.Code[1:], 10, 8)
	logInit(sealedlog.Record{Component: sealedlog.CompAtomInit, Code: sealedlog.BootDiagnosis,
		Args: []uint64{n, b2u(d.RollbackHelps)}})
}

// LogDataRepair keeps a check or repair of the data partition in the sealed
// log, with the verdict and whether the partition now checks clean.
func LogDataRepair(r Repair) {
	code := sealedlog.BootDataCheck
	if r.Fix != "" || r.Fixed {
		code = sealedlog.BootDataRepair
	}
	logInit(sealedlog.Record{Component: sealedlog.CompAtomInit, Code: code,
		Args: []uint64{uint64(r.Verdict), b2u(r.Fixed)}})
}

func b2u(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func logInit(r sealedlog.Record) {
	_ = sealedlog.MountEFIVars()
	lb, _ := sealedlog.ReadLoaderBoot()
	p := sealedlog.Payload{BaseUnixMs: uint64(time.Now().UnixMilli())}
	if b, err := sealedlog.ReadEFIVar(sealedlog.VarInit); err == nil {
		if e, err := sealedlog.ParseEarly(b); err == nil && e.Boot == lb.Boot {
			p = e.Payload
		}
	}
	if len(p.Records) >= maxInitRecords {
		return
	}
	p.Records = append(p.Records, r)
	out := binary.LittleEndian.AppendUint32(nil, lb.Boot)
	if err := sealedlog.WriteEFIVar(sealedlog.VarInit, append(out, p.Encode()...)); err != nil {
		Logf("sealed log: %v", err)
	}
}
