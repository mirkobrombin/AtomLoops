package boot

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDmTargetLayout(t *testing.T) {
	b := dmTarget(2048, 4096, "linear", "259:3 12288")
	le := binary.LittleEndian
	if le.Uint64(b[0:]) != 2048 || le.Uint64(b[8:]) != 4096 {
		t.Fatalf("start %d sectors %d", le.Uint64(b[0:]), le.Uint64(b[8:]))
	}
	if int(le.Uint32(b[20:])) != len(b) || len(b)%8 != 0 {
		t.Fatalf("next %d len %d", le.Uint32(b[20:]), len(b))
	}
	if strings.TrimRight(string(b[24:40]), "\x00") != "linear" || strings.TrimRight(string(b[40:]), "\x00") != "259:3 12288" {
		t.Fatalf("target %q params %q", b[24:40], b[40:])
	}
}

// TestOpenLinearReadsThePiecesInOrder needs root and device-mapper; it maps
// two pieces of a loop device in reverse order and reads them back.
func TestOpenLinearReadsThePiecesInOrder(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/dev/mapper/control"); err != nil {
		t.Skip("no device-mapper")
	}
	img := filepath.Join(t.TempDir(), "disk")
	data := make([]byte, 8*512)
	for i := range data {
		data[i] = byte(i / 512)
	}
	os.WriteFile(img, data, 0o644)
	out, err := exec.Command("losetup", "-f", "--show", "-r", img).Output()
	if err != nil {
		t.Skip("no loop device")
	}
	loop := strings.TrimSpace(string(out))
	defer exec.Command("losetup", "-d", loop).Run()
	node, err := OpenLinear("atom-linear-test", []Segment{{loop, 6, 2}, {loop, 1, 3}})
	if err != nil {
		t.Fatal(err)
	}
	defer CloseMapping("atom-linear-test")
	got, err := os.ReadFile(node)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5*512 {
		t.Fatalf("read %d bytes", len(got))
	}
	for i, want := range []byte{6, 7, 1, 2, 3} {
		if got[i*512] != want {
			t.Fatalf("sector %d holds %d, want %d", i, got[i*512], want)
		}
	}
}
