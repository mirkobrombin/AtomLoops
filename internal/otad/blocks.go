package otad

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const BlockSize = 4 << 20

var ErrNoBlocks = errors.New("release carries no block hashes")

func HashBlocks(path string, size int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, size)
	var out []string
	for {
		n, err := io.ReadFull(f, buf)
		if n > 0 {
			sum := sha256.Sum256(buf[:n])
			out = append(out, hex.EncodeToString(sum[:]))
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func (m Manifest) RootFSBlockPlan() (int, []string, error) {
	if m.RootFSBlockSize <= 0 || len(m.RootFSBlocks) == 0 {
		return 0, nil, ErrNoBlocks
	}
	if m.RootFSBlockSize > 64<<20 {
		return 0, nil, fmt.Errorf("release block size %d is out of range", m.RootFSBlockSize)
	}
	for _, h := range m.RootFSBlocks {
		if len(h) != 64 {
			return 0, nil, fmt.Errorf("release block hash %q is malformed", h)
		}
	}
	return m.RootFSBlockSize, m.RootFSBlocks, nil
}

func (m Manifest) ExpiredAt(now time.Time) bool {
	if m.Expires == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, m.Expires)
	return err != nil || !now.Before(t)
}
