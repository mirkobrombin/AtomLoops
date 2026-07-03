package diag

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedNow() time.Time { return time.Unix(1751414400, 0).UTC() } // 2025-07-02

func TestCollectFullCompactRoundtrip(t *testing.T) {
	dir := t.TempDir()
	cmdline := filepath.Join(dir, "cmdline")
	os.WriteFile(cmdline, []byte("root=/dev/mapper/vroot roothash=abc123 quiet\n"), 0o644)
	sess := filepath.Join(dir, "boot.log")
	os.WriteFile(sess, []byte("line1\nline2\nline3\n"), 0o644)

	cfg := Config{
		Stage: "boot",
		Error: "device-mapper: verity: metadata block 1 is corrupted",
		Sources: []Source{
			{Label: "cmdline", Path: cmdline},
			{Label: "dmesg", Cmd: "printf 'a\\nb\\nc\\nd\\ne\\n'"},
			{Label: "failed-units", Cmd: "printf 'sintylogs.service\\n'"},
			{Label: "session", Path: sess},
			{Label: "missing", Path: filepath.Join(dir, "nope")}, // best-effort empty
		},
	}
	b := Collect(cfg, fixedNow)

	full := string(b.Full())
	if !strings.Contains(full, "verity: metadata block") || !strings.Contains(full, "===== cmdline =====") || !strings.Contains(full, "roothash=abc123") {
		t.Fatalf("full bundle missing content:\n%s", full)
	}
	if b.ID() == "" || len(b.ID()) != 8 {
		t.Fatalf("bad id %q", b.ID())
	}

	comp := string(b.Compact(3))
	for _, want := range []string{"stage: boot", "error: device-mapper", "id: " + b.ID(), "cmdline: root=/dev/mapper/vroot", "failed: sintylogs.service", "dmesg-tail:", "c\nd\ne"} {
		if !strings.Contains(comp, want) {
			t.Errorf("compact missing %q in:\n%s", want, comp)
		}
	}
	if strings.Contains(comp, "\na\n") { // only last 3 dmesg lines kept
		t.Errorf("compact kept too many dmesg lines:\n%s", comp)
	}

	// QR payload roundtrip: strip header, base64url-decode, gunzip.
	enc := string(EncodeQRPayload([]byte(comp)))
	if !strings.HasPrefix(enc, "SINTY-FAIL v1\n") {
		t.Fatalf("missing header: %q", enc[:20])
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.SplitN(enc, "\n", 2)[1])
	if err != nil {
		t.Fatal(err)
	}
	gz, _ := gzip.NewReader(bytes.NewReader(raw))
	got, _ := io.ReadAll(gz)
	if string(got) != comp {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestCompactWithinBudget(t *testing.T) {
	// a big dmesg that would blow any small budget; header fields stay, tail shrinks
	big := make([]byte, 0, 40000)
	for i := 0; i < 2000; i++ {
		big = append(big, []byte("kernel: some noisy diagnostic line number here\n")...)
	}
	b := Bundle{
		Stage: "boot", Error: "verity corrupted", When: "2026-07-03T00:00:00Z",
		Sections: []Section{
			{Label: "cmdline", Data: []byte("root=/dev/mapper/vroot roothash=deadbeef")},
			{Label: "failed-units", Data: []byte("sintylogs.service")},
			{Label: "dmesg", Data: big},
		},
	}
	for _, budget := range []int{600, 1200, 1800} {
		compact, encoded, kept := b.CompactWithin(budget)
		if len(encoded) > budget {
			t.Errorf("budget %d: encoded %d bytes exceeds", budget, len(encoded))
		}
		if !strings.Contains(string(compact), "stage: boot") || !strings.Contains(string(compact), "error: verity corrupted") || !strings.Contains(string(compact), "roothash=deadbeef") {
			t.Errorf("budget %d: header fields dropped", budget)
		}
		if kept < 0 {
			t.Errorf("negative kept")
		}
	}
}
