# Components

Atom Loops is a small set of components with sharp boundaries: a daemon that
prepares updates, a signing chain and release tooling, an early-boot engine, and a
UEFI loader. The Go code builds `atomd` and `atom-sign`; the loader is Zig.

## Map

| Component | Path | Role |
| --- | --- | --- |
| Deployment WAL | `internal/deployment` | The `deployment.json` write-ahead log, the single source of truth for slot state. |
| OTA daemon | `internal/otad` + `cmd/atomd` | Boot confirmation, staging, anti-rollback reconciliation, recovery entry. |
| Trust and signing | `internal/trust` + `internal/signing` + `cmd/atom-sign` | The two-level key chain (root, signing certificate, manifest) and the release tooling. |
| Initramfs engine | `scripts/boot/initramfs-main.go` | dm-verity setup and the atomic switch before `switch_root`. |
| UEFI loader | `loader/` | Boot-slot selection and signature verification before chainloading the kernelcache. |

## The daemon (`atomd`)

`atomd` is the long-running side. It confirms a candidate boot, stages verified
updates into the inactive slot, reconciles the hardware anti-rollback counter with
the write-ahead log, and hands off to recovery when there is nothing good to boot.
It only ever writes the boot-state crash-durably; it never switches the running
system out from under itself.

## The signing tooling (`atom-sign`)

`atom-sign` is the release-side tool. It produces the signed artifacts the daemon
later verifies: the signing certificate and revocation list under the root key,
and the update manifest under the signing key. See [Trust model](../security/trust-model.md)
for the chain it builds.

## The initramfs engine

`scripts/boot/initramfs-main.go` is compiled into the initramfs. It runs before
`switch_root`: it sets up dm-verity for the target root and performs the atomic
slot switch, and it never falls back to a raw, unverified device. It is the last
gate before the real system takes over.

## The loader

`loader/` is the Zig UEFI loader. It selects the boot slot and verifies the
image's signature before chainloading, so an unverified kernelcache never runs.
It is built separately from the Go tree.

## Building

```bash
go build ./...             # atomd (daemon) + atom-sign (release tool)
cd loader && sh build.sh   # BOOTX64.EFI (needs Zig 0.16)
```

Requirements: **Go >= 1.26** for the daemon and release tools, **Zig 0.16** for
the loader.
