package deployment

import "fmt"

// Slot names an on-disk artifact position. Artifacts are FILES, not partitions:
// the ESP holds kernelcache-active/-prev/-next/-recovery.efi and /boot/rootfs
// holds rootfs-active/-prev (a staged candidate lands in the "next" position).
type Slot string

const (
	SlotActive   Slot = "active"   // the running / stable image
	SlotNext     Slot = "next"     // a staged candidate being tried
	SlotPrev     Slot = "prev"     // the previous image, used for rollback
	SlotRecovery Slot = "recovery" // the independent, root-key-signed recovery image
)

// PickBootTarget is the single authority for slot selection: given the WAL state
// it returns which rootfs slot and which kernelcache slot the initramfs must
// boot. The initramfs engine and the OTA daemon both call this so the choice
// never drifts between them. rootfs and kernelcache are coupled 1:1, so both
// return the same slot (active->active, next->next, prev->prev); Recovery is the
// one exception where both come from the recovery image.
//
// The mapping:
//   - a candidate with boot budget remaining -> next (try the candidate)
//   - a candidate whose budget is spent, with a last_known_good -> prev (roll back)
//   - a candidate whose budget is spent, with no fallback -> recovery
//   - no candidate -> active (stable)
//
// NOTE for B: this assumes the previous image is reachable in the "prev" slot and
// that last_known_good's artifacts live there (there is one rootfs fallback slot).
// If your artifact layout differs, this is the one place to adjust.
func PickBootTarget(d *Deployment) (rootfs, kc Slot, err error) {
	if d == nil {
		return "", "", fmt.Errorf("deployment: nil WAL")
	}
	switch {
	case d.NeedsRecovery():
		return SlotRecovery, SlotRecovery, nil
	case d.HasPending() && d.RootFS.BootAttempts <= 0:
		return SlotPrev, SlotPrev, nil
	case d.HasPending():
		return SlotNext, SlotNext, nil
	default:
		return SlotActive, SlotActive, nil
	}
}
