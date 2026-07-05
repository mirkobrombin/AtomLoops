// Package atom is the public API surface of Atom Loops that external consumers
// build on (for example the Sinty recovery image): the signed staging and
// verification pipeline, the deployment WAL, and slot promotion and rollback.
// The implementation lives in the internal packages; this package re-exports the
// stable entry points so a separate module can reuse them without vendoring.
package atom

import (
	"context"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/otad"
)

// StageDirs names the on-disk slot directories (rootfs and ESP).
type StageDirs = otad.StageDirs

// Deployment is the update state recorded in the WAL.
type Deployment = deployment.Deployment

// Stage fetches and two-tier-verifies a signed manifest and its artifacts into
// the -next slots and marks the candidate pending in the WAL. revocationURL may
// be empty; rootPub is the caller's embedded ROOT public key.
func Stage(ctx context.Context, walPath, manifestURL, revocationURL string, rootPub []byte, dirs StageDirs) (string, error) {
	return otad.Stage(ctx, walPath, manifestURL, revocationURL, rootPub, dirs)
}

// Rollback returns to last_known_good with no network (its artifacts are already
// present) -- the guaranteed-safe recovery floor.
func Rollback(walPath string, dirs StageDirs) (string, error) {
	return otad.Rollback(walPath, dirs)
}

// SyncBootState derives the ESP boot-state from the WAL so the loader boots the
// slot the deployment expects.
func SyncBootState(walPath string, dirs StageDirs) error {
	return otad.SyncBootState(walPath, dirs)
}

// LoadDeployment reads the deployment WAL.
func LoadDeployment(walPath string) (*Deployment, error) {
	return deployment.Load(walPath)
}

// NewDeployment builds a fresh deployment record (installers and tests).
func NewDeployment(deviceID, rootfsVersion string) *Deployment {
	return deployment.New(deviceID, rootfsVersion)
}
