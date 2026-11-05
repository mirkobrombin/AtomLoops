package sealedlog

import (
	"encoding/hex"
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

// CounterIndex is the TPM NV counter of the sealed log, next to the
// anti-rollback counter of the loader (0x0150A701).
const CounterIndex = 0x0150A702

// Counter reads and advances the boot counter of the log. A ring that is
// put back from an older copy carries counters below the TPM value, which
// the reader reports.
type Counter interface {
	Increment() (uint64, error)
	Read() (uint64, error)
}

// TPMCounter drives the NV counter through tpm2-tools.
type TPMCounter struct {
	Index uint32
	Run   func(name string, args ...string) ([]byte, error)
}

func (t TPMCounter) run(name string, args ...string) ([]byte, error) {
	if t.Run != nil {
		return t.Run(name, args...)
	}
	return exec.Command(name, args...).Output()
}

func (t TPMCounter) index() string {
	i := t.Index
	if i == 0 {
		i = CounterIndex
	}
	return "0x" + strconv.FormatUint(uint64(i), 16)
}

// Read returns the counter value.
func (t TPMCounter) Read() (uint64, error) {
	out, err := t.run("tpm2_nvread", t.index(), "-C", t.index(), "-s", "8", "--offset", "0")
	if err != nil {
		return 0, err
	}
	if len(out) == 8 {
		var v uint64
		for _, c := range out {
			v = v<<8 | uint64(c)
		}
		return v, nil
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(raw) != 8 {
		return 0, errors.New("sealedlog: unreadable TPM counter")
	}
	var v uint64
	for _, c := range raw {
		v = v<<8 | uint64(c)
	}
	return v, nil
}

// Increment defines the counter when it is missing, advances it and returns
// the new value.
func (t TPMCounter) Increment() (uint64, error) {
	if _, err := t.run("tpm2_nvincrement", t.index(), "-C", t.index()); err != nil {
		if _, derr := t.run("tpm2_nvdefine", t.index(), "-C", "o", "-s", "8",
			"-a", "nt=counter|ownerread|ownerwrite|authread|authwrite|no_da"); derr != nil {
			return 0, err
		}
		if _, err := t.run("tpm2_nvincrement", t.index(), "-C", t.index()); err != nil {
			return 0, err
		}
	}
	return t.Read()
}

// Rollback reports whether the newest block of the log is older than the TPM
// counter allows: the ring was replaced with an earlier copy.
func Rollback(entries []Entry, tpm uint64) bool {
	var max uint64
	for _, e := range entries {
		if e.Header.Counter > max {
			max = e.Header.Counter
		}
	}
	return max != 0 && max < tpm
}
