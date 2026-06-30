// Package recovery is the Atom Loops recovery-mode API. It runs in the
// independent recovery image and exposes, over HTTP, the state of the WAL and the
// recovery actions that need no network: report status and roll back to
// last_known_good (whose artifacts are already on the device). Reinstall from a
// source is the one action that needs the network.
//
// The HTTP layer is go-foundation's srv (the service tier), while the WAL and the
// transitions stay in the shared deployment package.
package recovery

import (
	"github.com/mirkobrombin/atomloops/internal/audit"
	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/otad"
	"github.com/mirkobrombin/go-foundation/pkg/srv"
)

// New builds the recovery HTTP server bound to the given WAL path. auditPath is
// the update-history log surfaced at GET /history (empty disables it).
func New(walPath, auditPath string) *srv.Server {
	s := srv.New()

	// GET /history -- the append-only update history, for the operator.
	s.MapGet("/history", func(c *srv.Context) error {
		if auditPath == "" {
			return c.JSON(200, []audit.Event{})
		}
		events, err := audit.Read(auditPath)
		if err != nil {
			return c.JSON(500, map[string]string{"error": err.Error()})
		}
		if events == nil {
			events = []audit.Event{}
		}
		return c.JSON(200, events)
	})

	// GET /status -- the current deployment state, for the operator/UART.
	s.MapGet("/status", func(c *srv.Context) error {
		d, err := deployment.Load(walPath)
		if err != nil {
			return c.JSON(500, map[string]string{"error": err.Error()})
		}
		return c.JSON(200, map[string]any{
			"current":         d.RootFS.Current,
			"pending":         d.RootFS.Pending,
			"rollback":        d.RootFS.Rollback,
			"last_known_good": d.RootFS.LastKnownGood,
			"boot_attempts":   d.RootFS.BootAttempts,
			"recovery":        d.Recovery.Version,
			"kernelcache":     d.Kernelcache.CurrentVersion,
			"security_level":  d.Security.Level,
		})
	})

	// POST /rollback -- return to last_known_good with no network (its artifacts
	// are already present). The guaranteed-safe recovery floor.
	s.MapPost("/rollback", func(c *srv.Context) error {
		msg, err := otad.Rollback(walPath)
		if err != nil {
			return c.JSON(500, map[string]string{"error": err.Error()})
		}
		d, _ := deployment.Load(walPath)
		return c.JSON(200, map[string]any{"result": msg, "current": d.RootFS.Current})
	})

	return s
}
