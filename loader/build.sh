#!/usr/bin/env sh
# Build the Atom Loops EFI loader. Pinned to Zig 0.16.0 (pre-1.0: pin the toolchain).
# Produces bootx64.efi, a PE32+ UEFI application, ready for the ESP at
# EFI/BOOT/BOOTX64.EFI (or as the chain-loaded app before the UKI).
set -e
ZIG="${ZIG:-zig}"
if [ ! -f src/root.pub ]; then
  echo "ERROR: src/root.pub missing. Generate it once: atom-sign keygen --pub src/root.pub" >&2
  exit 1
fi
sz=$(wc -c < src/root.pub)
[ "$sz" = 32 ] || { echo "ERROR: src/root.pub is $sz bytes, expected 32 (raw Ed25519 pubkey)" >&2; exit 1; }
echo "embedding root key fingerprint: $(sha256sum src/root.pub | cut -c1-16)"
"$ZIG" build-exe src/main.zig -target x86_64-uefi -O ReleaseSmall --name bootx64
echo "built: $(file bootx64.efi)"
