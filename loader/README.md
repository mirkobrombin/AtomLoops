# Atom Loops EFI loader (prototype)

A thin custom UEFI loader (v1 feature-complete; QEMU+OVMF+swtpm verified) for the "one continuous surface" boot: it paints frame
zero of the surface in EFI, reads `deployment.json` from the ESP to pick the image
(active / pending / recovery via the shared slot-selection logic), measures into the
TPM, and chain-loads the signed UKI, preserving the framebuffer so there is no black
frame at handoff.

Written in **Zig** (pinned 0.16.0), in a deliberately Go-explicit style: every
fallible call is checked at the call site, no hidden control flow, no panics in
normal paths. Zig was picked because `std.os.uefi` is in-tree (offline builds,
no external deps), and `zig cc` / `@cImport` make it our incremental C-replacement
for the rest of the native bits (boot-splash, preload shims, utilities) too.

## Status
- [x] Phase 1: toolchain + UEFI entry + console banner -> `bootx64.efi` (PE32+ EFI app)
- [x] Phase 2: GOP frame-zero surface paint (fills the backdrop color)
- [x] Phase 6: read ESP deployment.json + PickBootTarget slot select -> chainload (QEMU-verified)
- [x] Phase 7: Ed25519 self-verify of the selected slot before chaining (QEMU-verified, valid accepted + tampered rejected)
- [x] Phase 3-4: LoadImage/StartImage chainload from the ESP (QEMU-verified via stage2)
- [ ] Phase 5: TPM PCR measurement; hidden in-surface image chooser

## Build
    ./build.sh        # needs zig 0.16.0 on PATH (or ZIG=/path/to/zig)

## Test (later)
Boot bootx64.efi under QEMU + OVMF, or drop it on an ESP as EFI/BOOT/BOOTX64.EFI.
