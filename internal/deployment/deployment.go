// Package deployment models deployment.json, the Atom Loops write-ahead log
// (WAL) that records the atomic-update state of a device: which rootfs and
// kernelcache are current, which is a pending candidate, which is the last
// known good, and the counters that drive automatic rollback and stabilization.
//
// The schema mirrors Atom Loops Architecture v4.6 section A6.1. The same file is
// read and written by two Go components with a strict split of ownership:
//
//   - the initramfs engine (early boot): reads the WAL to pick the boot target,
//     and performs exactly ONE write per boot -- decrementing rootfs.boot_attempts
//     -- rolling back to last_known_good (or Recovery) when it hits zero.
//   - the OTA daemon (running system): stages candidates, records good boots,
//     promotes a candidate to last_known_good after stable_threshold good boots,
//     and arms the hardware anti-rollback counter.
//
// The init (sinit) never touches this file.
package deployment

// Deployment is the root of deployment.json (schema A6.1).
type Deployment struct {
	RootFS        RootFS       `json:"rootfs"`
	Kernelcache   Kernelcache  `json:"kernelcache"`
	Recovery      Recovery     `json:"recovery"`
	Security      Security     `json:"security"`
	AntiRollback  AntiRollback `json:"anti_rollback"`
	OrphanHomes   []string     `json:"orphan_homes"`
	RecoveryEntry string       `json:"recovery_entry"`
	Meta          Meta         `json:"meta"`
}

// RootFS tracks the erofs rootfs images and the boot-attempt counter.
//
// current is the version being run (a candidate counts as current once switched
// to); rollback is the previous version to fall back to; last_known_good is the
// version that has accumulated at least stable_threshold consecutive good boots
// and is the guaranteed-safe recovery reference. pending is a staged candidate
// awaiting its first boot; it is "" (not null in Go) when there is none, matching
// the PoC initramfs which reads it as a string.
type RootFS struct {
	Current         string `json:"current"`
	Pending         string `json:"pending"`
	// PendingHash is the candidate's dm-verity root hash (the value baked into its signed
	// UKI cmdline as ATOM_ROOT_HASH). The daemon compares it to the hash the init actually
	// booted so it never confirms a candidate the loader silently fell back away from.
	PendingHash     string `json:"pending_hash,omitempty"`
	Rollback        string `json:"rollback"`
	BootAttempts    int    `json:"boot_attempts"`
	MaxAttempts     int    `json:"max_attempts"`
	LastKnownGood   string `json:"last_known_good"`
	LastKnownGoodAt string `json:"last_known_good_at"`
}

// Kernelcache tracks the UKI / kernel-cache versions and the stabilization
// counter that gates promotion of the ESP fallback (BOOTX64.EFI).
type Kernelcache struct {
	CurrentVersion  int    `json:"current_version"`
	PendingVersion  int    `json:"pending_version"`
	State           string `json:"state"`
	StableBoots     int    `json:"stable_boots"`
	StableThreshold int    `json:"stable_threshold"`
	Format          string `json:"format"`
}

// Recovery is the third, root-key-signed image; never replaced by a normal OTA.
type Recovery struct {
	Version     string `json:"version"`
	Path        string `json:"path"`
	LastUpdated string `json:"last_updated"`
}

// Security records the active security level (L1-L5) and the primitives in use.
type Security struct {
	Level             int    `json:"level"`
	DMVerity          bool   `json:"dm_verity"`
	SecureBoot        bool   `json:"secure_boot"`
	IMA               bool   `json:"ima"`
	SigningCert       string `json:"signing_cert"`
	RemoteAttestation bool   `json:"remote_attestation"`
}

// AntiRollback records the hardware monotonic counter (TPM2/RPMB) or, at L1, the
// software min_version floor. counter_value is written only after a candidate
// reaches stable_threshold, so a faulty update can never advance it.
type AntiRollback struct {
	Hardware     string `json:"hardware"`
	CounterValue int    `json:"counter_value"`
	LastUpdated  string `json:"last_updated"`
}

// Meta is device/channel bookkeeping.
type Meta struct {
	SchemaVersion   int    `json:"schema_version"`
	DeviceID        string `json:"device_id"`
	Channel         string `json:"channel"`
	LastUpdateCheck string `json:"last_update_check"`
}

// Kernelcache states.
const (
	KCStable   = "stable"   // no candidate in flight
	KCUpdating = "updating" // a candidate is staged or being stabilized
)

// HasPending reports whether a candidate is staged or being stabilized.
func (d *Deployment) HasPending() bool { return d.RootFS.Pending != "" }

// Clone returns a deep copy, so callers can stage a transition and only commit
// (Save) it if every step succeeds.
func (d *Deployment) Clone() *Deployment {
	c := *d
	c.OrphanHomes = append([]string(nil), d.OrphanHomes...)
	return &c
}
