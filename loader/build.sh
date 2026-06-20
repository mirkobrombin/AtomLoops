#!/usr/bin/env sh
# Build the Atom Loops EFI loader. Pinned to Zig 0.16.0 (pre-1.0: pin the toolchain).
# Produces bootx64.efi, a PE32+ UEFI application, ready for the ESP at
# EFI/BOOT/BOOTX64.EFI (or as the chain-loaded app before the UKI).
set -e
ZIG="${ZIG:-zig}"
"$ZIG" build-exe src/main.zig -target x86_64-uefi -O ReleaseSmall --name bootx64
echo "built: $(file bootx64.efi)"
