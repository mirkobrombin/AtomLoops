# CLI and daemon

Atom Loops builds two binaries from the Go tree: the on-device daemon `atomd` and
the release-side signing tool `atom-sign`. The UEFI loader is built separately from
`loader/`.

```bash
go build ./...             # atomd + atom-sign
cd loader && sh build.sh   # BOOTX64.EFI (needs Zig 0.16)
```

## `atomd` (device daemon)

`atomd` runs on the device and owns the deployment side of the lifecycle:

- **Boot confirmation.** On a stable boot it confirms the running candidate and
  promotes it, only ever confirming an image the system actually booted into.
- **Staging.** It checks revocation, verifies the signed manifest and artifacts,
  downloads what changed, and stages the verified image into the inactive slot.
- **Anti-rollback reconciliation.** It reconciles the hardware anti-rollback
  counter with the write-ahead log on a stable boot.
- **Recovery entry.** When there is no good image to boot, it hands off to
  recovery.

It writes the boot-state crash-durably and never switches the running system out
from under itself. See [Components](../architecture/components.md) and
[The deployment WAL](../architecture/wal.md).

## `atom-sign` (release tool)

`atom-sign` is the release-side tool that produces the signed artifacts the device
later verifies: the signing certificate and revocation list under the root key,
and the update manifest under the signing key. It is the tool that implements the
producing half of the [trust model](../security/trust-model.md).

The concrete, ordered commands for cutting a release, from generating keys to
signing the manifest, are in the [release runbook](../RELEASE-RUNBOOK.md), which is
kept as the authoritative operational reference so the steps stay in one place.

## The loader

The Zig UEFI loader in `loader/` selects the boot slot and verifies the image
signature before chainloading the kernelcache. It is built with `sh build.sh` and
requires Zig 0.16. It has a silent-by-default trace that can be turned on to follow
a boot on headless hardware.
