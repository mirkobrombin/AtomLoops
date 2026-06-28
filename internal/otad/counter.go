package otad

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// CounterStore is the monotonic anti-rollback counter (A4.2). It is advanced only
// after a candidate reaches stable_threshold good boots (at promotion), so a faulty
// update can never move the floor. Backends: FileCounter (software, L1) now; TPM2
// and RPMB (L4/L5) slot in behind the same interface with the hardware present.
type CounterStore interface {
	Read() (uint64, error)
	// Advance moves the counter toward `to`. It is monotonic: a value at or below
	// the current one is a no-op, never a regression.
	Advance(to uint64) error
}

// FileCounter is a software CounterStore backed by a single file. It gives L1
// anti-rollback (survives reboots, not physical tampering) and is the fallback
// where no TPM/RPMB is present.
type FileCounter struct{ Path string }

func (f FileCounter) Read() (uint64, error) {
	b, err := os.ReadFile(f.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("counter: bad value in %s: %w", f.Path, err)
	}
	return n, nil
}

func (f FileCounter) Advance(to uint64) error {
	cur, err := f.Read()
	if err != nil {
		return err
	}
	if to <= cur {
		return nil // monotonic: never regress
	}
	tmp := f.Path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatUint(to, 10)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.Path)
}
