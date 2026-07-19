# Anti-rollback

Signature checking stops a *forged* image. It does not, on its own, stop a
*genuine but old* image: an attacker could serve a real, correctly signed previous
release to reintroduce a fixed vulnerability. Anti-rollback is what closes that
door.

## The counter

Atom Loops tracks a monotonic anti-rollback counter. An update carries a minimum
counter value, and the boot chain refuses to run an image whose value is below the
device's recorded counter. Once the device has advanced past a version, that
version can no longer be booted, even though its signature is still valid.

!!! note "Status"
    The anti-rollback logic is implemented and reconciled through the write-ahead
    log. Validation against hardware roots (TPM 2.0 and RPMB) is not yet done; see
    the [roadmap](../roadmap.md), milestone M4.

## Reconciliation with the WAL

A crash can leave the hardware counter and the software state briefly out of step:
the log may be promoted while the counter still lags, or the reverse. On a stable
boot the daemon reconciles the two, advancing the counter to match the confirmed
deployment so that a later downgrade is caught. This reconciliation is why the
counter can be trusted after an interrupted update.

## Hardware anchoring

The stronger form of anti-rollback binds the counter to hardware that cannot be
rewound by software: a TPM 2.0 monotonic counter, or the replay-protected memory
block (RPMB) of an eMMC. This makes a downgrade resistant even to an attacker with
write access to the normal storage. Hardware anchoring is on the roadmap and not
yet validated against real TPM or RPMB devices.
