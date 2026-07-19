# Integrating Atom Loops

Atom Loops consumes a finished, signed system image and owns the deploy and
rollback lifecycle around it. To put an OS on Atom Loops you provide the image and
the signed metadata; Atom Loops does the rest. This page describes the contract.

!!! note "Status"
    This describes the integration contract as it stands against the first target,
    [Sinty OS](https://github.com/singularityos-lab). A fully general integration
    guide and a reproducible build environment are still in progress (roadmap
    milestone M7). Expect details to firm up as more targets come online.

## What you provide

1. **A whole, bootable image.** Atom Loops does not build or customize the OS. You
   ship a complete image, produced by whatever tooling you like. The system root
   is immutable and carries no editable state.
2. **A verity hash for the root.** The root is run under dm-verity, so the image
   must come with its verity metadata for the boot-time integrity check.
3. **A signed manifest.** The manifest lists the image's version, its artifacts and
   their SHA256 hashes. It is signed with your operational signing key.
4. **A key chain.** A cold root key signs a signing certificate and a revocation
   list; the signing key signs manifests. See [Trust model](security/trust-model.md).

## What the device needs

- **An ESP.** Beyond a small EFI System Partition, Atom Loops does not require a
  fixed A/B partition layout with two full copies of the OS.
- **The loader and initramfs engine.** The Zig UEFI loader and the initramfs engine
  handle slot selection, signature verification, dm-verity setup and the atomic
  switch. See [Components](architecture/components.md).
- **`atomd`.** The daemon runs on the device to prepare and stage updates.

## The update feed

Because [trust is the signature, not the transport](security/trust-model.md), the
update feed can be any host that serves files: a static site, object storage, or
GitHub Releases. You publish the signed manifest and the artifacts it references;
the daemon fetches, re-verifies and stages them. A hostile host cannot substitute
an image without failing verification.

## Signing a release

Release artifacts are produced with `atom-sign` and the two-level key chain. The
exact commands for cutting and signing a release live in the
[release runbook](RELEASE-RUNBOOK.md).

## Current limits

- Only **x86_64 (UEFI)** is validated so far. The model is designed to be portable
  down to small boards and on to RISC-V, but other targets are not yet proven.
- **Zsync-style delta download** is not implemented; artifacts currently download
  in full.
- **FIT / U-Boot** support and `atom-enroll` are not started; UEFI is the only
  boot path today.

See the [roadmap](roadmap.md) for the full picture of what is implemented and what
is not.
