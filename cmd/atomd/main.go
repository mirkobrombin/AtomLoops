// Command atomd is the Atom Loops OTA daemon: the running-system half of the
// deployment.json WAL protocol. Run as a service under the init.
//
//	atomd boot-success [--wal P] [--health-dir D]   greenboot: confirm/promote a candidate
//	atomd status       [--wal P]                    print the WAL summary
//	atomd stage --manifest URL [--wal P] [--pubkey F] fetch+verify+stage a signed update
//	atomd deploy <ver> [--wal P]                    mark a local candidate pending (WAL only)
//	atomd run [--manifest URL] [--wal P] [--cron C]  daemon: greenboot at start + scheduled update checks
//	atomd rollback     [--wal P]                    return to last_known_good
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mirkobrombin/atomloops/internal/audit"
	"github.com/mirkobrombin/atomloops/internal/otad"
	"github.com/mirkobrombin/atomloops/internal/recovery"
	"github.com/mirkobrombin/go-foundation/pkg/scheduler"
)

// runDaemon is atomd as a long-running service under the init: it confirms/promotes
// the current boot (greenboot) at startup, then, if a manifest is configured, checks
// for updates on a schedule (go-foundation's scheduler) and stages any it verifies.
// Blocks until SIGTERM/SIGINT.
// pickCounter selects the anti-rollback backend: the command-driven hardware
// counter (TPM2/RPMB) when both shell commands are given, otherwise the software
// file counter.
func pickCounter(filePath, readCmd, advanceCmd string) otad.CounterStore {
	if readCmd != "" && advanceCmd != "" {
		return otad.CommandCounter{ReadCmd: readCmd, AdvanceCmd: advanceCmd}
	}
	return otad.FileCounter{Path: filePath}
}

func runDaemon(wal, healthDir string, store otad.CounterStore, auditPath, manifestURL, revocationURL, pubkeyPath, cron, installedMarker string, dirs otad.StageDirs) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if !isInstalled(installedMarker) {
		fmt.Printf("atomd: live/uninstalled system (no %s), staying inert: no boot-success, no counter, no update checks\n", installedMarker)
		<-ctx.Done()
		return 0
	}

	if msg, err := otad.BootSuccess(wal, healthDir, store, dirs); err != nil {
		fmt.Fprintln(os.Stderr, "atomd: boot-success:", err)
	} else {
		fmt.Println(msg)
		audit.Append(auditPath, "boot-success", msg, time.Now)
	}

	sched := scheduler.New(scheduler.WithLogger(func(m string) { fmt.Println("atomd:", m) }))
	if manifestURL != "" {
		pubkey, err := os.ReadFile(pubkeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "atomd: read pubkey: %v\n", err)
			return 1
		}
		sched.Register(scheduler.Job{
			Name: "update-check",
			Cron: cron,
			Handler: func(ctx context.Context) error {
				msg, err := otad.Stage(ctx, wal, manifestURL, revocationURL, pubkey, dirs)
				if err == nil {
					fmt.Println("atomd:", msg)
					audit.Append(auditPath, "stage", msg, time.Now)
				}
				return err
			},
		})
	}
	if err := sched.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "atomd:", err)
		return 1
	}
	<-ctx.Done()
	_ = sched.Stop(context.Background())
	return 0
}

const defaultWAL = "/boot/rootfs/deployment.json"
const defaultHealthDir = "/etc/atom/health.d"
const defaultCounter = "/var/lib/atom/anti-rollback"
const defaultAudit = "/var/log/atom/history.jsonl"

// defaultInstalledMarker is written by the initramfs only when it mounts a real,
// same-disk persistent /var (an installed system). A live USB boot gets tmpfs /var
// and no marker. atomd fails safe: without this marker it never confirms a boot,
// advances the anti-rollback counter, or stages -- so a live boot on someone
// else's machine cannot touch that machine's per-machine hardware state (TPM/RPMB).
const defaultInstalledMarker = "/run/atom/installed"

// isInstalled reports whether this is an installed system (marker present).
func isInstalled(marker string) bool {
	_, err := os.Stat(marker)
	return err == nil
}

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "init":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		wal := fs.String("wal", defaultWAL, "path to deployment.json")
		dev := fs.String("device-id", "unknown", "device id to record")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "atomd init: needs exactly one <version> (flags before it)")
			return 2
		}
		return report(otad.Init(*wal, *dev, fs.Arg(0)))
	case "run":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		wal := fs.String("wal", defaultWAL, "path to deployment.json")
		hd := fs.String("health-dir", defaultHealthDir, "health-check executables dir")
		manifest := fs.String("manifest", "", "manifest URL to poll for updates (empty = greenboot only)")
		pubkeyPath := fs.String("pubkey", "/etc/atom/root.pub", "root public key file")
		cron := fs.String("cron", "0 * * * *", "update-check cron (default hourly)")
		revocation := fs.String("revocation", "", "root-signed revocation list URL (empty to skip)")
		counter := fs.String("counter", defaultCounter, "anti-rollback counter file")
		counterRead := fs.String("counter-read", "", "shell command printing the hardware counter (TPM2/RPMB); overrides --counter")
		counterAdvance := fs.String("counter-advance", "", "shell command to advance the hardware counter (ATOM_COUNTER=target)")
		auditPath := fs.String("audit", defaultAudit, "update-history log")
		installed := fs.String("installed-marker", defaultInstalledMarker, "path the initramfs writes on an installed system; absent = live, atomd inert")
		rootfsDir := fs.String("rootfs-dir", "/boot/rootfs", "where rootfs-next lands")
		espDir := fs.String("esp-dir", "/boot/efi/EFI/atom", "where kernelcache-next lands")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		return runDaemon(*wal, *hd, pickCounter(*counter, *counterRead, *counterAdvance), *auditPath, *manifest, *revocation, *pubkeyPath, *cron, *installed,
			otad.StageDirs{Rootfs: *rootfsDir, ESP: *espDir})
	case "recover":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		wal := fs.String("wal", defaultWAL, "path to deployment.json")
		addr := fs.String("addr", ":7654", "recovery HTTP listen address")
		auditPath := fs.String("audit", defaultAudit, "update-history log for /history")
		rootfsDir := fs.String("rootfs-dir", "/boot/rootfs", "rootfs slot dir (for rollback boot-state)")
		espDir := fs.String("esp-dir", "/boot/efi/EFI/atom", "ESP slot dir (for rollback boot-state)")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		fmt.Printf("atomd: recovery API on %s\n", *addr)
		if err := recovery.New(*wal, *auditPath, otad.StageDirs{Rootfs: *rootfsDir, ESP: *espDir}).ListenAndServe(*addr); err != nil {
			fmt.Fprintln(os.Stderr, "atomd:", err)
			return 1
		}
		return 0
	case "stage":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		wal := fs.String("wal", defaultWAL, "path to deployment.json")
		manifest := fs.String("manifest", "", "signed manifest URL to fetch")
		pubkeyPath := fs.String("pubkey", "/etc/atom/root.pub", "root public key file (32 raw bytes)")
		revocation := fs.String("revocation", "", "root-signed revocation list URL (empty to skip)")
		rootfsDir := fs.String("rootfs-dir", "/boot/rootfs", "where rootfs-next lands")
		espDir := fs.String("esp-dir", "/boot/efi/EFI/atom", "where kernelcache-next lands")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if *manifest == "" {
			fmt.Fprintln(os.Stderr, "atomd stage: --manifest URL required")
			return 2
		}
		pubkey, err := os.ReadFile(*pubkeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "atomd stage: read pubkey: %v\n", err)
			return 1
		}
		return report(otad.Stage(context.Background(), *wal, *manifest, *revocation, pubkey,
			otad.StageDirs{Rootfs: *rootfsDir, ESP: *espDir}))
	case "boot-success":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		wal := fs.String("wal", defaultWAL, "path to deployment.json")
		hd := fs.String("health-dir", defaultHealthDir, "directory of health-check executables")
		counter := fs.String("counter", defaultCounter, "anti-rollback counter file")
		counterRead := fs.String("counter-read", "", "shell command printing the hardware counter (TPM2/RPMB); overrides --counter")
		counterAdvance := fs.String("counter-advance", "", "shell command to advance the hardware counter (ATOM_COUNTER=target)")
		installed := fs.String("installed-marker", defaultInstalledMarker, "path the initramfs writes on an installed system; absent = live, boot-success is a no-op")
		rootfsDir := fs.String("rootfs-dir", "/boot/rootfs", "rootfs slot dir (for promote rename + boot-state)")
		espDir := fs.String("esp-dir", "/boot/efi/EFI/atom", "ESP slot dir (for promote rename + boot-state)")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if !isInstalled(*installed) {
			fmt.Printf("atomd: live/uninstalled system (no %s), boot-success is a no-op\n", *installed)
			return 0
		}
		return report(otad.BootSuccess(*wal, *hd, pickCounter(*counter, *counterRead, *counterAdvance), otad.StageDirs{Rootfs: *rootfsDir, ESP: *espDir}))
	case "status":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		wal := fs.String("wal", defaultWAL, "path to deployment.json")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		return report(otad.Status(*wal))
	case "deploy":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		wal := fs.String("wal", defaultWAL, "path to deployment.json")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "atomd deploy: needs exactly one <version>")
			return 2
		}
		return report(otad.Deploy(*wal, fs.Arg(0)))
	case "rollback":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		wal := fs.String("wal", defaultWAL, "path to deployment.json")
		rootfsDir := fs.String("rootfs-dir", "/boot/rootfs", "rootfs slot dir (for boot-state)")
		espDir := fs.String("esp-dir", "/boot/efi/EFI/atom", "ESP slot dir (for boot-state)")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		return report(otad.Rollback(*wal, otad.StageDirs{Rootfs: *rootfsDir, ESP: *espDir}))
	case "version", "--version", "-v":
		fmt.Printf("atomd %s\n", version)
		return 0
	default:
		usage()
		return 2
	}
}

func report(msg string, err error) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "atomd: %v\n", err)
		return 1
	}
	fmt.Println(msg)
	return 0
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: atomd <init|run|recover|stage|boot-success|status|deploy|rollback|version> [flags]")
}
