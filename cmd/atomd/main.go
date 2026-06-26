// Command atomd is the Atom Loops OTA daemon: the running-system half of the
// deployment.json WAL protocol. Run as a service under the init.
//
//	atomd boot-success [--wal P] [--health-dir D]   greenboot: confirm/promote a candidate
//	atomd status       [--wal P]                    print the WAL summary
//	atomd stage --manifest URL [--wal P] [--pubkey F] fetch+verify+stage a signed update
//	atomd deploy <ver> [--wal P]                    mark a local candidate pending (WAL only)
//	atomd rollback     [--wal P]                    return to last_known_good
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/mirkobrombin/atomloops/internal/otad"
)

const defaultWAL = "/boot/rootfs/deployment.json"
const defaultHealthDir = "/etc/atom/health.d"

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
	case "stage":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		wal := fs.String("wal", defaultWAL, "path to deployment.json")
		manifest := fs.String("manifest", "", "signed manifest URL to fetch")
		pubkeyPath := fs.String("pubkey", "/etc/atom/root.pub", "root public key file (32 raw bytes)")
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
		return report(otad.Stage(context.Background(), *wal, *manifest, pubkey,
			otad.StageDirs{Rootfs: *rootfsDir, ESP: *espDir}))
	case "boot-success":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		wal := fs.String("wal", defaultWAL, "path to deployment.json")
		hd := fs.String("health-dir", defaultHealthDir, "directory of health-check executables")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		return report(otad.BootSuccess(*wal, *hd))
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
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		return report(otad.Rollback(*wal))
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
	fmt.Fprintln(os.Stderr, "usage: atomd <boot-success|status|deploy <ver>|rollback|version> [--wal PATH] [--health-dir DIR]")
}
