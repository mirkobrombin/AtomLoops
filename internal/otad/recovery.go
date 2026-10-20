package otad

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/trust"
)

const (
	recoveryFile     = "kernelcache-recovery.efi"
	recoveryNextFile = "kernelcache-recovery-next.efi"
	recoveryPrevFile = "kernelcache-recovery-prev.efi"
)

type RecoveryStatus struct {
	Installed string `json:"installed"`
	Available string `json:"available,omitempty"`
	Current   bool   `json:"current"`
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func RecoveryIsCurrent(dirs StageDirs, m *Manifest) bool {
	if m.RecoveryHash == "" {
		return true
	}
	got, err := fileSHA256(filepath.Join(dirs.ESP, recoveryFile))
	return err == nil && got == m.RecoveryHash
}

func RepairRecoverySlot(dirs StageDirs) (string, error) {
	if dirs.ESP == "" {
		return "", nil
	}
	cur := filepath.Join(dirs.ESP, recoveryFile)
	prev := filepath.Join(dirs.ESP, recoveryPrevFile)
	if _, err := os.Stat(cur); err == nil {
		if _, err := os.Stat(cur + ".sig"); err == nil {
			os.Remove(prev)
			os.Remove(prev + ".sig")
			return "", nil
		}
	}
	if _, err := os.Stat(prev); err != nil {
		return "", nil
	}
	if err := os.Rename(prev, cur); err != nil {
		return "", fmt.Errorf("recovery: restore previous image: %w", err)
	}
	if err := os.Rename(prev+".sig", cur+".sig"); err != nil {
		return "", fmt.Errorf("recovery: restore previous signature: %w", err)
	}
	if err := commitDir(dirs.ESP); err != nil {
		return "", err
	}
	return "recovery: an interrupted update was rolled back to the previous recovery", nil
}

func StageRecovery(ctx context.Context, walPath, manifestURL, revocationURL string, rootPub []byte, dirs StageDirs) (string, error) {
	if dirs.ESP == "" {
		return "", errors.New("recovery: no ESP configured")
	}
	d, err := deployment.Load(walPath)
	if err != nil {
		return "", err
	}
	if d.HasPending() {
		return "", errors.New("recovery: a system update is waiting for a reboot, finish it first")
	}
	if _, err := RepairRecoverySlot(dirs); err != nil {
		return "", err
	}
	work, err := os.MkdirTemp("", "atomd-recovery-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	vm, err := fetchVerifiedManifest(ctx, work, manifestURL, revocationURL, rootPub, "")
	if err != nil {
		return "", err
	}
	m := vm.manifest
	if m.RecoveryURL == "" || m.RecoverySigURL == "" || m.RecoveryHash == "" {
		return "", errors.New("recovery: this release carries no recovery image")
	}
	if RecoveryIsCurrent(dirs, &m) {
		return "recovery: already current", nil
	}
	os.Remove(filepath.Join(dirs.ESP, "kernelcache-next.efi"))
	next := filepath.Join(dirs.ESP, recoveryNextFile)
	cleanup := func() {
		os.Remove(next)
		os.Remove(next + ".sig")
	}
	if _, err := FetchTo(ctx, m.RecoveryURL, next); err != nil {
		cleanup()
		return "", err
	}
	if err := VerifySHA256(next, m.RecoveryHash); err != nil {
		cleanup()
		return "", err
	}
	if _, err := FetchTo(ctx, m.RecoverySigURL, next+".sig"); err != nil {
		cleanup()
		return "", err
	}
	if err := VerifySHA256(next+".sig", m.RecoverySigHash); err != nil {
		cleanup()
		return "", err
	}
	img, err := os.ReadFile(next)
	if err != nil {
		cleanup()
		return "", err
	}
	sig, err := os.ReadFile(next + ".sig")
	if err != nil {
		cleanup()
		return "", err
	}
	signingPub, _, err := trust.VerifyCert(vm.cert, vm.certSig, rootPub, time.Now())
	if err != nil {
		cleanup()
		return "", fmt.Errorf("recovery: %w", err)
	}
	if !trust.Verify(img, sig, signingPub) {
		cleanup()
		return "", errors.New("recovery: signature invalid, refusing")
	}
	if err := commitDir(dirs.ESP); err != nil {
		cleanup()
		return "", err
	}
	cur := filepath.Join(dirs.ESP, recoveryFile)
	prev := filepath.Join(dirs.ESP, recoveryPrevFile)
	if _, err := os.Stat(cur); err == nil {
		if err := os.Rename(cur, prev); err != nil {
			cleanup()
			return "", fmt.Errorf("recovery: keep previous image: %w", err)
		}
		os.Rename(cur+".sig", prev+".sig")
	}
	if err := os.Rename(next+".sig", cur+".sig"); err != nil {
		return "", fmt.Errorf("recovery: install signature: %w", err)
	}
	if err := os.Rename(next, cur); err != nil {
		return "", fmt.Errorf("recovery: install image: %w", err)
	}
	if err := commitDir(dirs.ESP); err != nil {
		return "", err
	}
	syscall.Sync()
	os.Remove(prev)
	os.Remove(prev + ".sig")
	commitDir(dirs.ESP)

	if d, err := deployment.Load(walPath); err == nil {
		d.Recovery.Version = strconv.Itoa(m.RecoveryVersion)
		d.Recovery.LastUpdated = time.Now().UTC().Format(time.RFC3339)
		d.Save(walPath)
	}
	return fmt.Sprintf("recovery: version %d installed", m.RecoveryVersion), nil
}
