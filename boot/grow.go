package boot

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// F2FSResizer is where the initramfs carries resize.f2fs.
const F2FSResizer = "/sbin/resize.f2fs"

const (
	f2fsSuperOffset = 1024
	f2fsMagic       = 0xf2f52010
)

// F2FSBytes reads the size an f2fs filesystem was made with from its
// superblock, or 0 when dev does not start with one.
func F2FSBytes(r io.ReaderAt) uint64 {
	sb := make([]byte, 48)
	if _, err := r.ReadAt(sb, f2fsSuperOffset); err != nil {
		return 0
	}
	le := binary.LittleEndian
	if le.Uint32(sb) != f2fsMagic {
		return 0
	}
	logBlock := le.Uint32(sb[16:])
	if logBlock < 9 || logBlock > 16 {
		return 0
	}
	return le.Uint64(sb[36:]) << logBlock
}

// GrowData grows the f2fs filesystem on dev to the whole partition. A phone's
// data image is flashed at the size of its contents, far smaller than the
// partition, and grows here on its first boot.
func GrowData(dev string) error {
	f, err := os.Open(dev)
	if err != nil {
		return err
	}
	fs := F2FSBytes(f)
	f.Close()
	part := DevBytes(dev)
	if fs == 0 || part == 0 || fs+(64<<20) >= part {
		return nil
	}
	Logf("data partition %s: growing f2fs from %d to %d MiB", dev, fs>>20, part>>20)
	out, err := exec.Command(F2FSResizer, dev).CombinedOutput()
	if err != nil {
		return fmt.Errorf("resize.f2fs %s: %v: %s", dev, err, tail(out, 512))
	}
	return nil
}

func tail(b []byte, n int) []byte {
	if len(b) > n {
		return b[len(b)-n:]
	}
	return b
}
