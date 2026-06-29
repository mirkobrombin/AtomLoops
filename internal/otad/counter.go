package otad

import (
	"fmt"
	"os"
	"os/exec"
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

// CommandCounter is a CounterStore backed by external shell commands, so the real
// hardware counter (a TPM2 NV counter via tpm2-tools, or an RPMB helper) is
// configured by the operator rather than hardcoded into the daemon. This is how
// L4/L5 slot in behind the interface without the daemon depending on TPM/RPMB
// libraries.
//
// ReadCmd must print the current counter value as a decimal integer on stdout.
// AdvanceCmd is run with the target value in the ATOM_COUNTER environment
// variable and is responsible for moving the hardware counter up to at least that
// value (e.g. a wrapper that calls tpm2_nvincrement until it reaches ATOM_COUNTER).
// Both run via "sh -c".
type CommandCounter struct {
	ReadCmd    string
	AdvanceCmd string
}

func (c CommandCounter) Read() (uint64, error) {
	out, err := exec.Command("sh", "-c", c.ReadCmd).Output()
	if err != nil {
		return 0, fmt.Errorf("counter read: %w", err)
	}
	s := strings.TrimSpace(string(out))
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("counter read: bad value %q: %w", s, err)
	}
	return n, nil
}

func (c CommandCounter) Advance(to uint64) error {
	cur, err := c.Read()
	if err != nil {
		return err
	}
	if to <= cur {
		return nil // monotonic: never regress
	}
	cmd := exec.Command("sh", "-c", c.AdvanceCmd)
	cmd.Env = append(os.Environ(), fmt.Sprintf("ATOM_COUNTER=%d", to))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("counter advance to %d: %w: %s", to, err, strings.TrimSpace(string(out)))
	}
	return nil
}
