# Roadmap

Atom Loops is under active development and not ready for production. This page is
the honest picture of what is implemented and what is not. It mirrors the roadmap
in the repository README.

| Milestone | Scope | Status |
| --- | --- | --- |
| M1 | Core engine: initramfs, WAL, atomic switch, dm-verity | Largely done |
| M2 | OTA daemon: download, cryptographic verification, deploy | Partial. Manifest verification, revocation and staging work. Zsync delta download is not implemented; artifacts download in full |
| M3 | Secure Boot and kernelcache: UKI and FIT | Partial. UKI only. FIT / U-Boot and `atom-enroll` not started |
| M4 | Hardware anti-rollback: TPM 2.0 and RPMB | Partial. Not validated against TPM or RPMB hardware |
| M5 | Recovery mode | Partial. The recovery agent lives in its own repository. The independent recovery image is not proven |
| M6 | Testing across the target hardware fleet | Not started. x86_64 only |
| M7 | CLI, documentation and public release | Partial. Release runbook and this documentation exist; no reproducible build environment yet |

## What this means in practice

- The **core deploy-and-boot loop** works end to end on x86_64 UEFI: stage, switch,
  verify, roll back on failure.
- **Cryptographic verification** of the manifest, revocation and artifacts is in
  place; the transport is untrusted by design.
- **Delta downloads, hardware anti-rollback anchoring, non-UEFI boot, and a proven
  standalone recovery image** are the main gaps.

The first and only fully exercised integration target so far is
[Sinty OS](https://github.com/singularityos-lab). Follow the repository for what
lands as it lands.
