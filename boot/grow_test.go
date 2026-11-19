package boot

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestF2FSBytes(t *testing.T) {
	img := make([]byte, 4096)
	le := binary.LittleEndian
	le.PutUint32(img[1024:], f2fsMagic)
	le.PutUint32(img[1024+16:], 12)
	le.PutUint64(img[1024+36:], 262144)
	if got := F2FSBytes(bytes.NewReader(img)); got != 1<<30 {
		t.Fatalf("got %d, want 1 GiB", got)
	}
	le.PutUint32(img[1024:], 0)
	if F2FSBytes(bytes.NewReader(img)) != 0 {
		t.Fatal("no superblock must read as 0")
	}
	if F2FSBytes(bytes.NewReader(img[:100])) != 0 {
		t.Fatal("a short device must read as 0")
	}
}
