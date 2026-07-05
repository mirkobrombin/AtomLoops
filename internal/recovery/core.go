package recovery

import (
	"context"
	"fmt"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/otad"
	"github.com/mirkobrombin/atomloops/internal/wifi"
)

// Config is what the recovery image bakes in: the interface to bring up, the WAL
// and slot dirs shared with the initramfs, and the update endpoints + embedded
// ROOT key used to verify a re-downloaded image.
type Config struct {
	Iface         string // e.g. "wlan0"
	WALPath       string
	ManifestURL   string
	RevocationURL string
	RootPub       []byte // the recovery image's baked-in ROOT public key
	Dirs          otad.StageDirs
}

// Core is the recovery logic shared by every front-end: the interactive TTY
// fallback (in-process) and the Cairo UI (over the local HTTP API) both drive
// these methods, so the two UIs can never drift in behavior.
type Core struct {
	cfg  Config
	wifi *wifi.Client
}

// NewCore builds the recovery core for the given config.
func NewCore(cfg Config) *Core {
	return &Core{cfg: cfg, wifi: wifi.New(cfg.Iface)}
}

// Scan lists reachable wireless networks.
func (c *Core) Scan(ctx context.Context) ([]wifi.Network, error) { return c.wifi.Scan(ctx) }

// Connect associates with a network (psk empty for open) and gets a DHCP lease.
func (c *Core) Connect(ctx context.Context, ssid, psk string) error {
	return c.wifi.Connect(ctx, ssid, psk)
}

// Status is the deployment state a UI shows the operator.
type Status struct {
	Current       string `json:"current"`
	Pending       string `json:"pending"`
	Rollback      string `json:"rollback"`
	LastKnownGood string `json:"last_known_good"`
	BootAttempts  int    `json:"boot_attempts"`
	Recovery      string `json:"recovery"`
	Kernelcache   int    `json:"kernelcache"`
	SecurityLevel int    `json:"security_level"`
}

// Status reads the current deployment state from the WAL.
func (c *Core) Status() (Status, error) {
	d, err := deployment.Load(c.cfg.WALPath)
	if err != nil {
		return Status{}, err
	}
	return Status{
		Current:       d.RootFS.Current,
		Pending:       d.RootFS.Pending,
		Rollback:      d.RootFS.Rollback,
		LastKnownGood: d.RootFS.LastKnownGood,
		BootAttempts:  d.RootFS.BootAttempts,
		Recovery:      d.Recovery.Version,
		Kernelcache:   d.Kernelcache.CurrentVersion,
		SecurityLevel: d.Security.Level,
	}, nil
}

// Reinstall fetches, verifies and stages a fresh signed image over the network.
func (c *Core) Reinstall(ctx context.Context) (string, error) {
	return Reinstall(ctx, c.cfg.WALPath, c.cfg.ManifestURL, c.cfg.RevocationURL, c.cfg.RootPub, c.cfg.Dirs)
}

// Rollback returns to last_known_good with no network (its artifacts are already
// present) -- the guaranteed-safe recovery floor.
func (c *Core) Rollback() (string, error) {
	return otad.Rollback(c.cfg.WALPath, c.cfg.Dirs)
}

// Repair tries the cheapest safe fix first: roll back to last_known_good if it
// exists. If there is nothing to roll back to, only a network reinstall can help,
// and we say so rather than pretend a repair is possible.
func (c *Core) Repair() (string, error) {
	d, err := deployment.Load(c.cfg.WALPath)
	if err != nil {
		return "", err
	}
	if d.RootFS.LastKnownGood == "" {
		return "", fmt.Errorf("no last_known_good to repair to; a network reinstall is required")
	}
	return otad.Rollback(c.cfg.WALPath, c.cfg.Dirs)
}
