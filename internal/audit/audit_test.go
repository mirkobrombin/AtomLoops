package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixedClock(sec int) func() time.Time {
	return func() time.Time { return time.Unix(int64(sec), 0).UTC() }
}

func TestAppendAndRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "history.jsonl")

	// Absent file reads as empty, not an error.
	if ev, err := Read(p); err != nil || ev != nil {
		t.Fatalf("empty read: %v %v", ev, err)
	}

	Append(p, "stage", "staged v2", fixedClock(100))
	Append(p, "boot-success", "promoted v2", fixedClock(200))
	Append(p, "rollback", "back to v1", fixedClock(300))

	ev, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 3 {
		t.Fatalf("got %d events, want 3", len(ev))
	}
	if ev[0].Action != "stage" || ev[2].Action != "rollback" {
		t.Errorf("order wrong: %+v", ev)
	}
	if ev[1].Detail != "promoted v2" {
		t.Errorf("detail wrong: %q", ev[1].Detail)
	}
}

func TestReadSkipsMalformed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "history.jsonl")
	Append(p, "stage", "ok", fixedClock(1))
	// A torn/garbage line must not break the rest.
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("{not json\n")
	f.Close()
	Append(p, "rollback", "ok2", fixedClock(2))

	ev, _ := Read(p)
	if len(ev) != 2 {
		t.Fatalf("got %d events, want 2 (malformed skipped)", len(ev))
	}
}
