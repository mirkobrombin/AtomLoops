package live

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// TPMDevice is the resource-managed TPM the measurement is sent to.
var TPMDevice = "/dev/tpmrm0"

const (
	tpmSTSessions  = 0x8002
	tpmCCPCRExtend = 0x00000182
	tpmRSPW        = 0x40000009
	tpmAlgSHA256   = 0x000B
)

// pcrExtendCommand builds TPM2_PCR_Extend of one SHA-256 digest into pcr with
// an empty password session.
func pcrExtendCommand(pcr int, digest [32]byte) []byte {
	b := make([]byte, 0, 64)
	b = binary.BigEndian.AppendUint16(b, tpmSTSessions)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint32(b, tpmCCPCRExtend)
	b = binary.BigEndian.AppendUint32(b, uint32(pcr))
	b = binary.BigEndian.AppendUint32(b, 9)
	b = binary.BigEndian.AppendUint32(b, tpmRSPW)
	b = binary.BigEndian.AppendUint16(b, 0)
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = binary.BigEndian.AppendUint16(b, tpmAlgSHA256)
	b = append(b, digest[:]...)
	binary.BigEndian.PutUint32(b[2:], uint32(len(b)))
	return b
}

// Measurement is what a live swap extends: the roots it went between.
func Measurement(class, from, fromHash, to, toHash string) [32]byte {
	return sha256.Sum256([]byte("atomloops-live-v1\x00" + class + "\x00" + from + "\x00" + fromHash + "\x00" + to + "\x00" + toHash))
}

func tpmTransmit(cmd []byte) ([]byte, error) {
	fd, err := syscall.Open(TPMDevice, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: TPMDevice, Err: err}
	}
	defer syscall.Close(fd)
	if _, err := syscall.Write(fd, cmd); err != nil {
		return nil, fmt.Errorf("live: TPM write: %w", err)
	}
	resp := make([]byte, 4096)
	n, err := syscall.Read(fd, resp)
	if err != nil {
		return nil, fmt.Errorf("live: TPM read: %w", err)
	}
	return resp[:n], nil
}

// ExtendPCR extends pcr of the SHA-256 bank with digest.
func ExtendPCR(pcr int, digest [32]byte) error {
	if pcr < 0 || pcr > 23 {
		return fmt.Errorf("live: PCR %d out of range", pcr)
	}
	resp, err := tpmTransmit(pcrExtendCommand(pcr, digest))
	if err != nil {
		return err
	}
	n := len(resp)
	if n < 10 {
		return errors.New("live: short TPM response")
	}
	if rc := binary.BigEndian.Uint32(resp[6:10]); rc != 0 {
		return fmt.Errorf("live: TPM2_PCR_Extend failed: 0x%x", rc)
	}
	return nil
}
