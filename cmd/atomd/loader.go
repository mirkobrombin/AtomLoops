package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/mirkobrombin/atomloops/internal/otad"
)

const defaultRootPub = "/etc/atom-fw-root.pub"

func runLoader(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: atomd loader status|update|repair [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("loader "+sub, flag.ContinueOnError)
	espDir := fs.String("esp-dir", "/boot/efi/EFI/atom", "ESP atom dir")
	wal := fs.String("wal", defaultWAL, "path to deployment.json")
	pubkeyPath := fs.String("pubkey", defaultRootPub, "root public key file (32 raw bytes)")
	manifest := fs.String("manifest", "", "signed manifest URL (update)")
	retry := fs.Bool("retry", false, "stage a loader version that failed before (update)")
	image := fs.String("image", "", "signed loader image (repair)")
	sigPath := fs.String("sig", "", "detached signature of the image (repair, default IMAGE.sig)")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	dirs := otad.StageDirs{ESP: *espDir}
	switch sub {
	case "status":
		b, _ := json.MarshalIndent(otad.ReadLoaderStatus(dirs), "", "  ")
		fmt.Println(string(b))
		return 0
	case "update":
		if *manifest == "" {
			fmt.Fprintln(os.Stderr, "atomd loader update: --manifest URL required")
			return 2
		}
		pub, err := os.ReadFile(*pubkeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "atomd loader update: read pubkey: %v\n", err)
			return 1
		}
		return report(otad.StageLoader(context.Background(), *wal, *manifest, "", pub, dirs, *retry))
	case "repair":
		if *image == "" {
			fmt.Fprintln(os.Stderr, "atomd loader repair: --image required")
			return 2
		}
		if *sigPath == "" {
			*sigPath = *image + ".sig"
		}
		pub, err := os.ReadFile(*pubkeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "atomd loader repair: read pubkey: %v\n", err)
			return 1
		}
		img, err := os.ReadFile(*image)
		if err != nil {
			fmt.Fprintf(os.Stderr, "atomd loader repair: %v\n", err)
			return 1
		}
		sig, err := os.ReadFile(*sigPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "atomd loader repair: %v\n", err)
			return 1
		}
		return report(otad.RepairLoader(dirs, img, sig, pub))
	}
	fmt.Fprintf(os.Stderr, "atomd loader: unknown subcommand %q\n", sub)
	return 2
}

func runRecovery(args []string) int {
	if len(args) == 0 || args[0] != "update" {
		fmt.Fprintln(os.Stderr, "usage: atomd recovery update --manifest URL [flags]")
		return 2
	}
	fs := flag.NewFlagSet("recovery update", flag.ContinueOnError)
	espDir := fs.String("esp-dir", "/boot/efi/EFI/atom", "ESP atom dir")
	wal := fs.String("wal", defaultWAL, "path to deployment.json")
	pubkeyPath := fs.String("pubkey", defaultRootPub, "root public key file (32 raw bytes)")
	manifest := fs.String("manifest", "", "signed manifest URL")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *manifest == "" {
		fmt.Fprintln(os.Stderr, "atomd recovery update: --manifest URL required")
		return 2
	}
	pub, err := os.ReadFile(*pubkeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "atomd recovery update: read pubkey: %v\n", err)
		return 1
	}
	return report(otad.StageRecovery(context.Background(), *wal, *manifest, "", pub, otad.StageDirs{ESP: *espDir}))
}
