package boot

import "github.com/mirkobrombin/atomloops/internal/otad"

// AnchorRelease names the release an anchor boot chose, empty otherwise.
func (m *Media) AnchorRelease() string {
	return m.Anchor.Manifest.Version
}

// CommitAnchorBoot runs once the root is mounted with the data partition
// writable under NewRoot: it spends one trial attempt when the chosen release is
// a candidate, as the loader does, and records the booted identity for the
// daemon. A boot that was not an anchor boot is left untouched.
func (m *Media) CommitAnchorBoot() error {
	if m.Anchor.Manifest.RootFSVerityHash == "" {
		return nil
	}
	if m.Anchor.Trial {
		if err := otad.SpendAnchorTrial(NewRoot + AnchorESP); err != nil {
			return err
		}
	}
	return otad.WriteBootIdentity(m.Anchor.Manifest.RootFSVerityHash, m.Anchor.Manifest.Version)
}
