// Package sealedlog is the sealed boot and session log of Atom Loops: a ring of
// fixed-size blocks, each one encrypted to a reader public key and chained to the
// previous block by hash. Writers (the EFI loader, the kernels, the init, the
// system services) hold only the public key, so a compromised writer can append
// but cannot read what was logged before. The reader private key is sealed in the
// TPM behind the user PIN.
//
// Events are not text. Each record is a component byte, an event byte, a time
// delta and up to three numeric arguments, so a whole boot fits in a few hundred
// bytes; the dictionary in dict.go turns them back into words.
package sealedlog

import (
	"encoding/binary"
	"errors"
)

// MaxArgs is the number of numeric arguments a record can carry.
const MaxArgs = 3

// Record is one event.
type Record struct {
	Component Component
	Code      Code
	// DeltaMs is the time since the previous record of the same block, or since
	// the block base time for the first record.
	DeltaMs uint64
	Args    []uint64
	// Blob carries raw bytes for CodeBlob records only, such as the tail of a
	// panic message that the kernel could not reduce to codes.
	Blob []byte
}

var errShort = errors.New("sealedlog: truncated record")

// AppendRecord encodes r at the end of dst.
func AppendRecord(dst []byte, r Record) []byte {
	n := len(r.Args)
	if n > MaxArgs {
		n = MaxArgs
	}
	dst = append(dst, byte(r.Component), byte(r.Code), byte(n))
	dst = binary.AppendUvarint(dst, r.DeltaMs)
	for _, a := range r.Args[:n] {
		dst = binary.AppendUvarint(dst, a)
	}
	if r.Code == CodeBlob {
		dst = binary.AppendUvarint(dst, uint64(len(r.Blob)))
		dst = append(dst, r.Blob...)
	}
	return dst
}

// Payload is the plaintext of one block: a base time and the records after it.
type Payload struct {
	// BaseUnixMs is the wall clock of the first record, 0 when the writer had
	// no clock.
	BaseUnixMs uint64
	Records    []Record
}

// Encode returns the payload bytes.
func (p Payload) Encode() []byte {
	b := binary.AppendUvarint(nil, p.BaseUnixMs)
	for _, r := range p.Records {
		b = AppendRecord(b, r)
	}
	return b
}

// DecodePayload parses payload bytes. Trailing zero padding is ignored.
func DecodePayload(b []byte) (Payload, error) {
	var p Payload
	base, n := binary.Uvarint(b)
	if n <= 0 {
		return p, errShort
	}
	p.BaseUnixMs = base
	b = b[n:]
	for len(b) > 0 {
		if len(b) < 3 {
			return p, errShort
		}
		if b[0] == 0 && b[1] == 0 && b[2] == 0 {
			break
		}
		r := Record{Component: Component(b[0]), Code: Code(b[1])}
		argc := int(b[2] & 3)
		b = b[3:]
		d, n := binary.Uvarint(b)
		if n <= 0 {
			return p, errShort
		}
		r.DeltaMs = d
		b = b[n:]
		for i := 0; i < argc; i++ {
			a, n := binary.Uvarint(b)
			if n <= 0 {
				return p, errShort
			}
			r.Args = append(r.Args, a)
			b = b[n:]
		}
		if r.Code == CodeBlob {
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return p, errShort
			}
			r.Blob = append([]byte(nil), b[n:n+int(l)]...)
			b = b[n+int(l):]
		}
		p.Records = append(p.Records, r)
	}
	return p, nil
}
