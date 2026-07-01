// Package trust implements the two-level Atom Loops trust chain (doc A4.1): a cold
// ROOT key signs short-lived SIGNING-key certificates and a revocation list; the
// operational SIGNING key signs update manifests. The daemon and the loader both
// verify against the same embedded root key, so the signing key can rotate without
// touching either. JSON is flat by contract so the Zig loader can parse it without
// a JSON library.
package trust

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// SigningCert conveys an operational signing public key, vouched for by the root
// key via a detached signature over the cert bytes.
type SigningCert struct {
	Version       int    `json:"version"`
	SigningPubkey string `json:"signing_pubkey"` // base64 of the 32-byte Ed25519 key
	IssuedAt      string `json:"issued_at"`      // RFC3339
	NotAfter      string `json:"not_after"`      // RFC3339
}

// Revocation is the root-signed revocation list, checked before every update.
type Revocation struct {
	MinCertVersion int    `json:"min_cert_version"` // reject any cert version below this
	Revoked        []int  `json:"revoked"`          // explicitly revoked cert versions
	UpdatedAt      string `json:"updated_at"`       // RFC3339
}

// Verify reports whether sig is a valid Ed25519 signature over data by pub. It is
// the one detached-signature primitive the whole chain uses.
func Verify(data, sig, pub []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), data, sig)
}

// VerifyCert verifies a signing certificate against the root key and returns the
// operational signing public key it vouches for. It fails if the root signature is
// invalid, the cert is malformed, or the cert has expired (not_after < now).
func VerifyCert(certBytes, certSig, rootPub []byte, now time.Time) (signingPub []byte, version int, err error) {
	if !Verify(certBytes, certSig, rootPub) {
		return nil, 0, fmt.Errorf("trust: signing cert not signed by the root key")
	}
	var c SigningCert
	if err := json.Unmarshal(certBytes, &c); err != nil {
		return nil, 0, fmt.Errorf("trust: bad cert json: %w", err)
	}
	pub, err := base64.StdEncoding.DecodeString(c.SigningPubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, 0, fmt.Errorf("trust: cert has a bad signing_pubkey")
	}
	if c.NotAfter != "" {
		exp, err := time.Parse(time.RFC3339, c.NotAfter)
		if err != nil {
			return nil, 0, fmt.Errorf("trust: cert has a bad not_after: %w", err)
		}
		if now.After(exp) {
			return nil, 0, fmt.Errorf("trust: signing cert v%d expired at %s", c.Version, c.NotAfter)
		}
	}
	return pub, c.Version, nil
}

// CheckRevocation verifies the revocation list against the root key and reports an
// error if certVersion is revoked or below the declared minimum. This runs FIRST
// in every update cycle, so a compromised signing key is shut out without a rootfs
// update.
func CheckRevocation(revBytes, revSig, rootPub []byte, certVersion int) error {
	if !Verify(revBytes, revSig, rootPub) {
		return fmt.Errorf("trust: revocation list not signed by the root key")
	}
	var r Revocation
	if err := json.Unmarshal(revBytes, &r); err != nil {
		return fmt.Errorf("trust: bad revocation json: %w", err)
	}
	if certVersion < r.MinCertVersion {
		return fmt.Errorf("trust: signing cert v%d is below the minimum v%d (revoked)", certVersion, r.MinCertVersion)
	}
	for _, v := range r.Revoked {
		if v == certVersion {
			return fmt.Errorf("trust: signing cert v%d is explicitly revoked", certVersion)
		}
	}
	return nil
}
