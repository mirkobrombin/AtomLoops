package peers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	Port = 7713

	magic = "SINTY-PEER-1"

	msgHello    byte = 1
	msgAccept   byte = 2
	msgRefuse   byte = 3
	msgBlock    byte = 4
	msgData     byte = 5
	msgManifest byte = 6
	msgRelease  byte = 7

	maxRequest = 64
	maxRelease = 1 << 20
)

type ID [32]byte

var (
	errFrame   = errors.New("peers: malformed frame")
	errRefused = errors.New("peers: the neighbour refused")
)

func writeFrame(w io.Writer, kind byte, payload []byte) error {
	head := make([]byte, 5, 5+len(payload))
	head[0] = kind
	binary.BigEndian.PutUint32(head[1:], uint32(len(payload)))
	_, err := w.Write(append(head, payload...))
	return err
}

func readFrame(r io.Reader, limit int) (byte, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[1:])
	if int64(n) > int64(limit) {
		return 0, nil, fmt.Errorf("%w: %d bytes", errFrame, n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return head[0], payload, nil
}

func helloPayload(id ID) []byte {
	return append([]byte(magic), id[:]...)
}

func parseHello(p []byte) (ID, bool) {
	var id ID
	if len(p) != len(magic)+len(id) || string(p[:len(magic)]) != magic {
		return id, false
	}
	copy(id[:], p[len(magic):])
	return id, true
}

type Bundle struct {
	Manifest, Sig, Cert, CertSig []byte
}

func (b Bundle) encode() []byte {
	var out []byte
	for _, part := range [][]byte{b.Manifest, b.Sig, b.Cert, b.CertSig} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(part)))
		out = append(out, part...)
	}
	return out
}

func decodeBundle(p []byte) (Bundle, error) {
	var parts [4][]byte
	for i := range parts {
		if len(p) < 4 {
			return Bundle{}, errFrame
		}
		n := binary.BigEndian.Uint32(p)
		p = p[4:]
		if uint64(n) > uint64(len(p)) {
			return Bundle{}, errFrame
		}
		parts[i], p = p[:n], p[n:]
	}
	if len(p) != 0 {
		return Bundle{}, errFrame
	}
	return Bundle{parts[0], parts[1], parts[2], parts[3]}, nil
}
