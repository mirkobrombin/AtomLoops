// Command atom-sign is the release-side signing tool for Atom Loops updates. It
// runs where images are built, not on the device.
//
//	atom-sign keygen [--priv root.key] [--pub root.pub]   generate the root keypair
//	atom-sign issue-cert --root root.key --version N       root-sign a signing cert + new signing key
//	atom-sign revoke --root root.key --min-version N       write a root-signed revocation list
//	atom-sign manifest --version V --rootfs F --rootfs-url U --kernelcache F --kc-url U
//	atom-sign sign --manifest M --priv signing-vN.key     write M + ".sig" (SIGNING key)
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mirkobrombin/atomloops/internal/signing"
)

func main() { os.Exit(run(os.Args[1:])) }

// bundleList is a repeatable --bundle flag; each value is a comma-separated key=val
// spec, e.g. name=intel-wifi,img=wifi.img,url=https://.../wifi.img,verity=<roothash>,
// hashtree=wifi.hash,hashtree-url=https://.../wifi.hash,version=3[,chips=iwlwifi|ath].
type bundleList []signing.FirmwareSpec

func (b *bundleList) String() string { return fmt.Sprintf("%d bundles", len(*b)) }

func (b *bundleList) Set(v string) error {
	var fw signing.FirmwareSpec
	for _, kv := range strings.Split(v, ",") {
		k, val, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("bundle field %q is not key=value", kv)
		}
		switch strings.TrimSpace(k) {
		case "name":
			fw.Name = val
		case "img", "image":
			fw.ImageFile = val
		case "url":
			fw.ImageURL = val
		case "verity", "verity-hash":
			fw.VerityHash = val
		case "hashtree":
			fw.HashTreeFile = val
		case "hashtree-url":
			fw.HashTreeURL = val
		case "version":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("bundle version %q: %w", val, err)
			}
			fw.Version = n
		case "min-version":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("bundle min-version %q: %w", val, err)
			}
			fw.MinVersion = n
		case "chips":
			fw.Chips = strings.Split(val, "|")
		case "critical", "critical-devices":
			fw.CriticalDevices = strings.Split(val, "|")
		case "kernel-min":
			fw.KernelMin = val
		case "kernel-max":
			fw.KernelMax = val
		default:
			return fmt.Errorf("unknown bundle field %q", k)
		}
	}
	if fw.Name == "" || fw.ImageFile == "" || fw.ImageURL == "" || fw.Version == 0 {
		return fmt.Errorf("bundle needs at least name, img, url, version")
	}
	*b = append(*b, fw)
	return nil
}

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
	case "issue-cert":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		root := fs.String("root", "root.key", "root private key (cold)")
		version := fs.Int("version", 0, "signing cert version N (monotonic)")
		validity := fs.Duration("validity", 365*24*time.Hour, "cert validity (default 1 year)")
		cert := fs.String("cert", "", "output cert path (default signing-cert-vN.json)")
		signingKey := fs.String("signing-key", "", "output signing private key (default signing-vN.key)")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if *version <= 0 {
			fmt.Fprintln(os.Stderr, "atom-sign issue-cert: --version N (>0) required")
			return 2
		}
		cp := *cert
		if cp == "" {
			cp = fmt.Sprintf("signing-cert-v%d.json", *version)
		}
		sk := *signingKey
		if sk == "" {
			sk = fmt.Sprintf("signing-v%d.key", *version)
		}
		if err := signing.IssueCert(*root, cp, sk, *version, *validity, time.Now()); err != nil {
			fmt.Fprintln(os.Stderr, "atom-sign:", err)
			return 1
		}
		fmt.Printf("wrote %s (+ .sig) and %s (keep the signing key safe, sign manifests with it)\n", cp, sk)
		return 0
	case "revoke":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		root := fs.String("root", "root.key", "root private key (cold)")
		minVersion := fs.Int("min-version", 0, "reject any signing cert below this version")
		revokedCSV := fs.String("revoked", "", "comma-separated cert versions to explicitly revoke")
		out := fs.String("out", "revocation/latest.json", "output revocation list path")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		var revoked []int
		for _, s := range strings.Split(*revokedCSV, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			n, err := strconv.Atoi(s)
			if err != nil {
				fmt.Fprintf(os.Stderr, "atom-sign revoke: bad --revoked value %q\n", s)
				return 2
			}
			revoked = append(revoked, n)
		}
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "atom-sign:", err)
			return 1
		}
		if err := signing.Revoke(*root, *out, *minVersion, revoked, time.Now()); err != nil {
			fmt.Fprintln(os.Stderr, "atom-sign:", err)
			return 1
		}
		fmt.Printf("wrote %s (+ .sig): min_version=%d revoked=%v\n", *out, *minVersion, revoked)
		return 0
	case "manifest":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		out := fs.String("out", "manifest.json", "output manifest path")
		version := fs.String("version", "", "new version (e.g. v2)")
		minVersion := fs.String("min-version", "", "anti-rollback floor version")
		productName := fs.String("product-name", "", "optional public product name")
		productVersion := fs.String("product-version", "", "optional public product version")
		productBuild := fs.String("product-build", "", "optional public product build")
		rootfs := fs.String("rootfs", "", "rootfs artifact file")
		rootfsURL := fs.String("rootfs-url", "", "URL the device will fetch the rootfs from")
		kc := fs.String("kernelcache", "", "kernelcache artifact file")
		kcURL := fs.String("kc-url", "", "URL the device will fetch the kernelcache from")
		rootfsVerity := fs.String("rootfs-verity-hash", "", "dm-verity root hash of the rootfs image (as baked in its UKI cmdline)")
		rootfsHT := fs.String("rootfs-hashtree", "", "rootfs dm-verity hash tree file")
		rootfsHTURL := fs.String("rootfs-hashtree-url", "", "URL the device will fetch the rootfs hash tree from")
		kcSig := fs.String("kc-sig", "", "loader signature file for the kernelcache")
		kcSigURL := fs.String("kc-sig-url", "", "URL the device will fetch the kernelcache signature from")
		fwImg := fs.String("firmware", "", "optional firmware add-on image file (erofs)")
		fwURL := fs.String("firmware-url", "", "URL the device will fetch the firmware image from")
		fwVerity := fs.String("firmware-verity-hash", "", "dm-verity root hash of the firmware image")
		fwHashTree := fs.String("firmware-hashtree", "", "firmware dm-verity hash tree file")
		fwHashTreeURL := fs.String("firmware-hashtree-url", "", "URL the device will fetch the firmware hash tree from")
		fwVersion := fs.Int("firmware-version", 0, "firmware track version")
		fwMinVersion := fs.Int("firmware-min-version", 0, "firmware anti-rollback floor")
		var bundles bundleList
		fs.Var(&bundles, "bundle", "repeatable multi-bundle spec (name=..,img=..,url=..,verity=..,hashtree=..,hashtree-url=..,version=..); supersedes --firmware")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if *version == "" || *rootfs == "" || *rootfsURL == "" || *kc == "" || *kcURL == "" {
			fmt.Fprintln(os.Stderr, "atom-sign manifest: --version, --rootfs, --rootfs-url, --kernelcache, --kc-url required")
			return 2
		}
		// An image without its hash tree, or a kernelcache without its signature, is an
		// update that stages fine and then fails to boot. Refuse to publish one.
		if *rootfsHT == "" || *rootfsHTURL == "" || *kcSig == "" || *kcSigURL == "" || *rootfsVerity == "" {
			fmt.Fprintln(os.Stderr, "atom-sign manifest: --rootfs-verity-hash, --rootfs-hashtree, --rootfs-hashtree-url, --kc-sig, --kc-sig-url required")
			return 2
		}
		if len(bundles) > 0 && *fwImg != "" {
			fmt.Fprintln(os.Stderr, "atom-sign manifest: use --bundle OR the single --firmware flags, not both")
			return 2
		}
		var fwSpec []signing.FirmwareSpec
		if len(bundles) > 0 {
			fwSpec = bundles
		} else if *fwImg != "" {
			if *fwURL == "" || *fwVerity == "" || *fwHashTree == "" || *fwHashTreeURL == "" || *fwVersion == 0 {
				fmt.Fprintln(os.Stderr, "atom-sign manifest: --firmware needs --firmware-url, --firmware-verity-hash, --firmware-hashtree, --firmware-hashtree-url, --firmware-version")
				return 2
			}
			fwSpec = []signing.FirmwareSpec{{
				Version: *fwVersion, MinVersion: *fwMinVersion,
				ImageFile: *fwImg, ImageURL: *fwURL,
				VerityHash:   *fwVerity,
				HashTreeFile: *fwHashTree, HashTreeURL: *fwHashTreeURL,
			}}
		}
		p, err := signing.BuildManifest(*out, signing.ReleaseSpec{
			Version: *version, MinVersion: *minVersion,
			ProductName: *productName, ProductVersion: *productVersion, ProductBuild: *productBuild,
			RootFSFile: *rootfs, RootFSURL: *rootfsURL,
			RootFSVerityHash:   *rootfsVerity,
			RootFSHashTreeFile: *rootfsHT, RootFSHashTreeURL: *rootfsHTURL,
			KernelcacheFile: *kc, KernelcacheURL: *kcURL,
			KernelcacheSigFile: *kcSig, KernelcacheSigURL: *kcSigURL,
		}, fwSpec...)
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
	fmt.Fprintln(os.Stderr, "usage: atom-sign <keygen|issue-cert|revoke|manifest|sign> [flags]")
}
