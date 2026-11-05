package sealedlog

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// Block layout, little endian, BlockSize bytes:
//
//	0   magic "SLG1"
//	4   ring     [16] identity of the ring the block was written for
//	20  seq      u64  global block sequence, never reused
//	28  boot     u32  boot number the block belongs to
//	32  counter  u64  TPM monotonic counter at that boot, 0 without a TPM
//	40  prev     [32] SHA-256 of the previous block (seq-1), zero for seq 1
//	72  ephemeral X25519 public key
//	104 nonce    [12]
//	116 ctlen    u16
//	118 ciphertext with the GCM tag, then zero padding
//
// The first 118 bytes are the additional data of the AEAD. The key is
// HKDF-SHA256(X25519(ephemeral, reader), salt = ephemeral || reader, info).
//
// A block never written holds "SLG0", the ring identity and its index, so a
// writer that reaches the disk by sector can prove a block belongs to the
// ring before it overwrites it.
const (
	BlockSize   = 4096
	headerSize  = 118
	tagSize     = 16
	MaxPayload  = BlockSize - headerSize - tagSize
	kdfInfo     = "sinty sealed log v1"
	offRing     = 4
	offSeq      = 20
	offBoot     = 28
	offCounter  = 32
	offPrev     = 40
	offEph      = 72
	offNonce    = 104
	offCtLen    = 116
	offIndex    = 20
	ephemeralSz = 32
)

var (
	magic      = [4]byte{'S', 'L', 'G', '1'}
	magicEmpty = [4]byte{'S', 'L', 'G', '0'}
)

var (
	ErrNotBlock   = errors.New("sealedlog: not a sealed block")
	ErrTooLarge   = errors.New("sealedlog: payload larger than a block")
	ErrOpen       = errors.New("sealedlog: block does not open with this key")
	ErrChainBreak = errors.New("sealedlog: hash chain broken")
)

// Header is the clear part of a block.
type Header struct {
	Ring    [16]byte
	Seq     uint64
	Boot    uint32
	Counter uint64
	Prev    [32]byte
}

func deriveKey(shared, eph, reader []byte) ([]byte, error) {
	salt := append(append([]byte{}, eph...), reader...)
	return hkdf.Key(sha256.New, shared, salt, kdfInfo, 32)
}

func gcm(key []byte) (cipher.AEAD, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(c)
}

// Seal builds one block holding payload, encrypted to reader.
func Seal(reader *ecdh.PublicKey, h Header, payload []byte, rnd io.Reader) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, ErrTooLarge
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	eph, err := ecdh.X25519().GenerateKey(rnd)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(reader)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(shared, eph.PublicKey().Bytes(), reader.Bytes())
	if err != nil {
		return nil, err
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	b := make([]byte, BlockSize)
	copy(b, magic[:])
	copy(b[offRing:], h.Ring[:])
	binary.LittleEndian.PutUint64(b[offSeq:], h.Seq)
	binary.LittleEndian.PutUint32(b[offBoot:], h.Boot)
	binary.LittleEndian.PutUint64(b[offCounter:], h.Counter)
	copy(b[offPrev:], h.Prev[:])
	copy(b[offEph:], eph.PublicKey().Bytes())
	if _, err := io.ReadFull(rnd, b[offNonce:offNonce+12]); err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint16(b[offCtLen:], uint16(len(payload)+tagSize))
	aead.Seal(b[headerSize:headerSize], b[offNonce:offNonce+12], payload, b[:headerSize])
	return b, nil
}

// ParseHeader reads the clear header of a block without opening it.
func ParseHeader(b []byte) (Header, error) {
	var h Header
	if len(b) < BlockSize || !bytes.Equal(b[:4], magic[:]) {
		return h, ErrNotBlock
	}
	if n := int(binary.LittleEndian.Uint16(b[offCtLen:])); n < tagSize || headerSize+n > BlockSize {
		return h, ErrNotBlock
	}
	copy(h.Ring[:], b[offRing:offRing+16])
	h.Seq = binary.LittleEndian.Uint64(b[offSeq:])
	h.Boot = binary.LittleEndian.Uint32(b[offBoot:])
	h.Counter = binary.LittleEndian.Uint64(b[offCounter:])
	copy(h.Prev[:], b[offPrev:offPrev+32])
	return h, nil
}

// EmptyBlock is the content of an unwritten block index of ring.
func EmptyBlock(ring [16]byte, index uint32) []byte {
	b := make([]byte, BlockSize)
	copy(b, magicEmpty[:])
	copy(b[offRing:], ring[:])
	binary.LittleEndian.PutUint32(b[offIndex:], index)
	return b
}

// RingOf returns the ring identity carried by a written or empty block.
func RingOf(b []byte) ([16]byte, bool) {
	var id [16]byte
	if len(b) < BlockSize || (!bytes.Equal(b[:4], magic[:]) && !bytes.Equal(b[:4], magicEmpty[:])) {
		return id, false
	}
	copy(id[:], b[offRing:offRing+16])
	return id, true
}

// Hash is the chain hash of a block: SHA-256 over header and ciphertext.
func Hash(b []byte) [32]byte {
	n := int(binary.LittleEndian.Uint16(b[offCtLen:]))
	return sha256.Sum256(b[:headerSize+n])
}

// Open decrypts a block with the reader private key.
func Open(reader *ecdh.PrivateKey, b []byte) (Header, []byte, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return h, nil, err
	}
	eph, err := ecdh.X25519().NewPublicKey(b[offEph : offEph+ephemeralSz])
	if err != nil {
		return h, nil, ErrNotBlock
	}
	shared, err := reader.ECDH(eph)
	if err != nil {
		return h, nil, ErrOpen
	}
	key, err := deriveKey(shared, eph.Bytes(), reader.PublicKey().Bytes())
	if err != nil {
		return h, nil, err
	}
	aead, err := gcm(key)
	if err != nil {
		return h, nil, err
	}
	n := int(binary.LittleEndian.Uint16(b[offCtLen:]))
	pt, err := aead.Open(nil, b[offNonce:offNonce+12], b[headerSize:headerSize+n], b[:headerSize])
	if err != nil {
		return h, nil, ErrOpen
	}
	return h, pt, nil
}
