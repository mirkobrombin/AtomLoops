// Command atom-sign is the release-side signing tool for Atom Loops updates. It
// runs where images are built, not on the device.
//
//	atom-sign keygen [--priv root.key] [--pub root.pub]   generate the root keypair
//	atom-sign manifest --version V --rootfs F --rootfs-url U --kernelcache F --kc-url U
//	atom-sign sign --manifest M [--priv root.key]         write M + ".sig"
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mirkobrombin/atomloops/internal/signing"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "keygen":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		priv := fs.String("priv", "root.key", "output path for the private key")
		pub := fs.String("pub", "root.pub", "output path for the public key")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if err := signing.GenerateKeyFiles(*priv, *pub); err != nil {
			fmt.Fprintln(os.Stderr, "atom-sign:", err)
			return 1
		}
		fmt.Printf("wrote %s (private) and %s (public)\n", *priv, *pub)
		return 0
	case "manifest":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		out := fs.String("out", "manifest.json", "output manifest path")
		version := fs.String("version", "", "new version (e.g. v2)")
		minVersion := fs.String("min-version", "", "anti-rollback floor version")
		rootfs := fs.String("rootfs", "", "rootfs artifact file")
		rootfsURL := fs.String("rootfs-url", "", "URL the device will fetch the rootfs from")
		kc := fs.String("kernelcache", "", "kernelcache artifact file")
		kcURL := fs.String("kc-url", "", "URL the device will fetch the kernelcache from")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if *version == "" || *rootfs == "" || *rootfsURL == "" || *kc == "" || *kcURL == "" {
			fmt.Fprintln(os.Stderr, "atom-sign manifest: --version, --rootfs, --rootfs-url, --kernelcache, --kc-url required")
			return 2
		}
		p, err := signing.BuildManifest(*out, *version, *minVersion, *rootfs, *rootfsURL, *kc, *kcURL)
		if err != nil {
			fmt.Fprintln(os.Stderr, "atom-sign:", err)
			return 1
		}
		fmt.Printf("wrote %s (sign it next)\n", p)
		return 0
	case "sign":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		priv := fs.String("priv", "root.key", "private key path")
		manifest := fs.String("manifest", "", "manifest file to sign")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if *manifest == "" {
			fmt.Fprintln(os.Stderr, "atom-sign sign: --manifest required")
			return 2
		}
		sigPath, err := signing.SignManifest(*priv, *manifest)
		if err != nil {
			fmt.Fprintln(os.Stderr, "atom-sign:", err)
			return 1
		}
		fmt.Printf("wrote %s\n", sigPath)
		return 0
	default:
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: atom-sign <keygen|manifest|sign> [flags] (see -h per subcommand)")
}
