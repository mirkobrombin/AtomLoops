# Atom Loops

Atomic OTA updates for Singularity OS: signed file-based artifacts, health-gated
boot confirmation, monotonic anti-rollback, and a custom UEFI loader. It runs as
a service under the init (sinit), never as PID 1, and owns the update lifecycle:
staging, boot confirmation, and rollback.

## Requirements

- Go >= 1.22 (daemon + release tools)
- Zig 0.16 (the UEFI loader, `loader/`)

## Build

```bash
go build ./...             # atomd (daemon) + atom-sign (release tool)
cd loader && sh build.sh   # BOOTX64.EFI (needs zig 0.16)
```

## Components

- `internal/deployment` - the deployment.json WAL (single source of truth).
- `internal/otad` + `cmd/atomd` - the daemon: boot confirmation, staging,
  anti-rollback, recovery.
- `internal/trust` + `internal/signing` + `cmd/atom-sign` - the two-level key
  chain (root cert, signing key, manifest) and the release tooling.
- `loader/` - the Zig UEFI loader: boot-slot selection and signature
  verification before chainloading the kernelcache.

## Security model

Two-level keys: a cold ROOT key signs a short-lived signing certificate and a
revocation list; the operational SIGNING key signs update manifests. The daemon
checks revocation first, then the cert against the root, then the manifest
against the signing key, then the artifacts by SHA256. See
[docs/RELEASE-RUNBOOK.md](docs/RELEASE-RUNBOOK.md).

## Relationship to sinit

Atom Loops does not replace the init. The running-system half (atomd) confirms or
rolls back the boot; [sinit](https://github.com/singularityos-lab/sinit) is PID 1.

## License

GPL-3.0 - see [LICENSE](LICENSE).
