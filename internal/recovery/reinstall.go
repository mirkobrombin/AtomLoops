package recovery

import (
	"context"
	"fmt"

	"github.com/mirkobrombin/atomloops/internal/otad"
)

// Reinstall is the one recovery action that needs the network: fetch a fresh,
// signed Sinty image from the update server, verify it end to end with the
// recovery image's OWN embedded ROOT key (independent of the possibly-dead main),
// stage it into the -next slot and point the boot-state at it. The caller then
// reboots; the normal boot-confirm flow tries the fresh candidate, and a good
// boot promotes it. If the fresh image also fails to boot, the loader's attempt
// counter drops the device back into recovery -- no worse off than before.
//
// The trust is the signature, not the transport. Stage runs the two-tier chain
// (revocation first, then the signing cert against rootPub, then the manifest
// against the signing key it vouches for), so a forged image served over a
// hostile wifi is rejected. rootPub is the recovery image's baked-in ROOT key.
func Reinstall(ctx context.Context, walPath, manifestURL, revocationURL string, rootPub []byte, dirs otad.StageDirs) (string, error) {
	msg, err := otad.Stage(ctx, walPath, manifestURL, revocationURL, rootPub, dirs)
	if err != nil {
		return "", fmt.Errorf("recovery reinstall: %w", err)
	}
	// Point the derived boot-state at the freshly staged candidate so the next
	// boot tries -next even if the old -active is the corrupt one we replaced.
	if err := otad.SyncBootState(walPath, dirs); err != nil {
		return "", fmt.Errorf("recovery reinstall: sync boot-state: %w", err)
	}
	return msg, nil
}
