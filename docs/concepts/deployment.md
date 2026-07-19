# Deployment lifecycle

The deployment side runs while the system is up. A background daemon prepares the
next update and stages it, but never switches anything on its own. The switch is a
boot-time decision, covered in [Boot lifecycle](boot.md).

<p align="center">
  <img src="../../img/deploy.png" alt="Deployment flow" width="480">
</p>

## The stages

The daemon walks an update through a fixed sequence. Each stage can abort the
update cleanly, leaving the running system untouched.

1. **Revocation check.** Before anything else, the daemon checks the revocation
   list signed by the root key. A revoked signing certificate stops the update
   here.
2. **Manifest verification.** The signed manifest describes the update: versions,
   artifacts and their hashes. It is checked against the signing certificate,
   which is itself checked against the root key.
3. **Version and hash comparison.** The daemon compares the manifest against the
   current deployment state to decide what actually needs to change.
4. **Download.** Only the changed artifacts are fetched. The transport is
   untrusted: an artifact served over any host or link is still authenticated by
   its signature and hash.
5. **Pre-verification.** Downloaded artifacts are re-verified by hash against the
   manifest before they are allowed near the staging slot.
6. **Staging.** The verified image is written into the inactive slot and its
   verity hash is recorded for the boot-time check. Nothing is switched yet.

## Nothing is switched until boot

At the end of a successful deployment the new image sits staged in the inactive
slot, recorded in the write-ahead log as a candidate. The running system is
unchanged. The decision to actually run the candidate belongs to the next boot,
which is where anti-rollback and the atomic switch happen. This split is what
makes a failed update a non-event: if staging is interrupted, the boot simply
never sees a candidate.

See [The deployment WAL](../architecture/wal.md) for how this state is recorded
crash-durably, and [Trust model](../security/trust-model.md) for the verification
chain.
