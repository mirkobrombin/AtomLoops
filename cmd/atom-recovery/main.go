// Command atom-recovery is the Sinty recovery agent: it brings up wifi with no
// desktop, then lets the operator reinstall a fresh signed Sinty over the network
// or repair the current one. It runs in the independent, disk-carved recovery
// image. The interactive text UI here is the graphics-free fallback; the Cairo UI
// drives the same Core over the local API.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/mirkobrombin/atomloops/internal/otad"
	"github.com/mirkobrombin/atomloops/internal/recovery"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("atom-recovery", flag.ContinueOnError)
	iface := fs.String("iface", "wlan0", "wireless interface to bring up")
	wal := fs.String("wal", "/var/lib/atom/deployment.json", "deployment WAL path")
	manifestURL := fs.String("manifest-url", "", "signed manifest URL on the update server")
	revocationURL := fs.String("revocation-url", "", "revocation list URL (optional)")
	rootPubPath := fs.String("root-pub", "/etc/atom/root.pub", "the recovery image's embedded ROOT public key")
	rootfsDir := fs.String("rootfs-dir", "/boot/rootfs", "rootfs slot directory")
	espDir := fs.String("esp-dir", "/boot/efi/EFI/atom", "ESP slot directory")
	mode := fs.String("mode", "tty", "tty (interactive console) | serve (local API, not yet)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	rootPub, err := os.ReadFile(*rootPubPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "atom-recovery: read ROOT key %s: %v\n", *rootPubPath, err)
		return 1
	}

	core := recovery.NewCore(recovery.Config{
		Iface:         *iface,
		WALPath:       *wal,
		ManifestURL:   *manifestURL,
		RevocationURL: *revocationURL,
		RootPub:       rootPub,
		Dirs:          otad.StageDirs{Rootfs: *rootfsDir, ESP: *espDir},
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch *mode {
	case "tty":
		if err := recovery.RunTTY(ctx, core); err != nil {
			fmt.Fprintln(os.Stderr, "atom-recovery:", err)
			return 1
		}
		return 0
	default:
		// The local HTTP API for the Cairo UI is pending its shape.
		fmt.Fprintf(os.Stderr, "atom-recovery: mode %q not yet implemented (use tty)\n", *mode)
		return 2
	}
}
