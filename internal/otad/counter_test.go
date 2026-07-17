package otad

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileCounterMonotonic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "count")
	c := FileCounter{Path: p}
	if v, _ := c.Read(); v != 0 {
		t.Fatalf("fresh counter = %d, want 0", v)
	}
	if err := c.Advance(43); err != nil {
		t.Fatal(err)
	}
	if v, _ := c.Read(); v != 43 {
		t.Fatalf("after advance = %d, want 43", v)
	}
	// Regress attempt is a no-op, never lowers the floor.
	if err := c.Advance(40); err != nil {
		t.Fatal(err)
	}
	if v, _ := c.Read(); v != 43 {
		t.Errorf("counter regressed to %d, want 43", v)
	}
}

func TestBootSuccessArmsCounter(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	wal := newWAL(t)
	if _, err := Deploy(wal, "v2"); err != nil {
		t.Fatal(err)
	}
	cnt := FileCounter{Path: filepath.Join(t.TempDir(), "count")}
	health := t.TempDir()
	for i := 0; i < 3; i++ {
		if _, err := BootSuccess(wal, health, cnt, StageDirs{}); err != nil {
			t.Fatal(err)
		}
	}
	// v2 promoted -> counter armed to the kernelcache version (2).
	if v, _ := cnt.Read(); v != 2 {
		t.Errorf("anti-rollback counter = %d, want 2 after promotion", v)
	}
}

type laggingCounter struct{ v uint64 }

func (c *laggingCounter) Read() (uint64, error) { return c.v, nil }
func (c *laggingCounter) Advance(to uint64) error {
	if to > c.v {
		c.v = to
	}
	return nil
}

// If a crash left the hardware anti-rollback counter behind the promoted WAL,
// a later stable boot must reconcile (retry the advance), not leave the floor lagged.
func TestBootSuccessReconcilesLaggedCounter(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	wal := newWAL(t)
	if _, err := Deploy(wal, "v2"); err != nil {
		t.Fatal(err)
	}
	health := t.TempDir()
	cnt := &laggingCounter{}
	for i := 0; i < 3; i++ { // promote v2 -> WAL CounterValue=2, counter armed to 2
		if _, err := BootSuccess(wal, health, cnt, StageDirs{}); err != nil {
			t.Fatal(err)
		}
	}
	cnt.v = 1 // simulate the crash: hardware floor left behind the promoted WAL (=2)
	if _, err := BootSuccess(wal, health, cnt, StageDirs{}); err != nil {
		t.Fatal(err)
	}
	if cnt.v != 2 {
		t.Fatalf("lagged counter not reconciled on a stable boot: got %d, want 2", cnt.v)
	}
}

func TestCommandCounter(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	f := filepath.Join(t.TempDir(), "hwcount")
	os.WriteFile(f, []byte("0"), 0o644)
	c := CommandCounter{ReadCmd: "cat " + f, AdvanceCmd: "echo $ATOM_COUNTER > " + f}

	if v, err := c.Read(); err != nil || v != 0 {
		t.Fatalf("read = %d, %v", v, err)
	}
	if err := c.Advance(5); err != nil {
		t.Fatal(err)
	}
	if v, _ := c.Read(); v != 5 {
		t.Fatalf("after advance = %d, want 5", v)
	}
	// Regress attempt is a no-op (monotonic), and does not run AdvanceCmd.
	if err := c.Advance(3); err != nil {
		t.Fatal(err)
	}
	if v, _ := c.Read(); v != 5 {
		t.Errorf("counter regressed to %d", v)
	}
}
