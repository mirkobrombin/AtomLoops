# Boot lifecycle

Deployment stages a candidate but never commits it. The boot is where the switch
actually happens, and where the system decides whether the new image is allowed to
stay. If it is not, the boot chain returns to the last good image on its own.

<p align="center">
  <img src="../../img/boot.png" alt="Boot layers" width="560">
</p>

## The layers

Booting an Atom Loops system passes through a chain of checks, each narrower than
the last:

1. **Firmware verifies the bootloader.** UEFI Secure Boot validates the loader
   before it runs.
2. **The loader selects a slot and verifies it.** The Zig UEFI loader picks the
   boot slot and checks the signature before chainloading the kernelcache. It will
   not hand control to an image it cannot verify.
3. **The initramfs decides whether to switch.** The early-boot engine reads the
   anti-rollback counter and the write-ahead log, sets up dm-verity for the target
   root, and performs the atomic slot switch before `switch_root`. A tampered or
   unverifiable root never boots.
4. **The runtime stabilizes and promotes.** After enough good boots, the daemon
   promotes the candidate to the confirmed image and the previous one becomes the
   fallback.

## Attempt counter and fallback

The boot is bounded by an attempt counter. Each try at a fresh candidate consumes
an attempt. If the candidate fails to come up and the counter runs out, the boot
chain falls back to the last good image, or drops into recovery if there is no
good image to return to. This is what makes a bad update self-healing: no human
has to intervene to get a working system back.

## Devices without a loader

Some devices cannot run the UEFI loader: a phone's bootloader, for one, boots the
kernel from its own boot partitions and never reads the ESP. There the initramfs
plays the loader's part. It reads the boot-state and the write-ahead log, picks the
candidate while its trial budget lasts and the installed release otherwise, and
takes the root hash from that release's signed manifest kept beside the slots
(`sing.roothash=anchor` on the command line). The release it chose is recorded in
`/run/atomloops/boot-identity`.

The kernel has to follow the root, so the system installs the kernelcache where
its bootloader finds it through executables in `/usr/lib/atomloops/kernel.d`.
Each runs with the phase as its argument, with `ATOM_KERNELCACHE` naming the
verified kernelcache, `ATOM_KERNELCACHE_HASH` its SHA256 from the signed manifest,
and `ATOM_VERSION` its release:

| Phase | When | What the hook does |
|---|---|---|
| `staged` | a candidate is verified on disk, before it is marked pending | installs the candidate's kernelcache; a failure refuses the candidate |
| `booted` | `updated sync-kernel` (`updated-sync-kernel.service`), early in every boot | installs the booted release's kernelcache if another one is in place, as after a candidate that failed its trial, and restarts the device |

A candidate that fails its trial brings back the installed root with the
candidate's kernel; the `booted` phase puts that release's own kernel back and
restarts, so the device returns to a matching pair on its own.

## dm-verity

The target root is set up under dm-verity before `switch_root`, so the running
system's integrity is enforced by the kernel block layer, not just checked once at
boot. A modification to the on-disk root surfaces as a verity error rather than
silently running.

See [Anti-rollback](../security/anti-rollback.md) for how downgrade attacks are
blocked, and [The deployment WAL](../architecture/wal.md) for the state the
initramfs reads.
