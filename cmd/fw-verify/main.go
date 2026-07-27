// fw-verify re-verifies the firmware boot anchor offline (root pubkey -> signing
// cert -> manifest) and prints the trusted dm-verity root hash on success. It is
// baked into the signed initramfs; the shell init calls it and feeds the hash to
// veritysetup. A missing, tampered or wrong-key anchor exits non-zero and the
// caller falls open to the base survival firmware, never brick. All trust logic is
// otad.VerifyFirmwareAnchor, so it stays byte-identical to the staging path.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/mirkobrombin/atomloops/internal/otad"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: fw-verify <bundle-dir> <slot> <rootpub-path> <bundle-name> [field]")
		fmt.Fprintln(os.Stderr, "  field: verity (default, prints the dm-verity root hash) | critical (prints the")
		fmt.Fprintln(os.Stderr, "         bundle's critical-device checks, one per line, for the early device-probe)")
		os.Exit(2)
	}
	dir, slot, rootPubPath, bundle := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	field := "verity"
	if len(os.Args) >= 6 {
		field = os.Args[5]
	}
	rootPub, err := os.ReadFile(rootPubPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fw-verify: root pub:", err)
		os.Exit(1)
	}
	fw, err := otad.VerifiedFirmwareBundle(dir, slot, rootPub, time.Now(), bundle)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fw-verify:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "fw-verify: firmware bundle %q v%d verified\n", bundle, fw.Version)
	switch field {
	case "verity":
		fmt.Println(fw.VerityHash)
	case "critical":
		for _, dev := range fw.CriticalDevices {
			fmt.Println(dev)
		}
	default:
		fmt.Fprintf(os.Stderr, "fw-verify: unknown field %q (want verity|critical)\n", field)
		os.Exit(2)
	}
}
