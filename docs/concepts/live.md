# Live apply

A staged candidate normally takes effect at the next boot. When a release allows
it, Atom Loops can also switch the running system to the candidate without a
reboot. The kernel keeps running, every process keeps running, and the root
filesystem underneath them is replaced by the verified image the next boot would
mount anyway.

Atom Loops only provides the mechanism. Whether an update may be applied live,
when, and what has to be restarted afterwards is the system's decision.

## What a release says

The signed manifest can carry an `apply` object:

```json
"apply": { "class": "reload", "live_from": "v41" }
```

- `class` is opaque to Atom Loops. It is lowercase letters, digits and dashes,
  and the system gives it a meaning (for example: apply silently, ask first,
  apply between two sessions). Atom Loops passes it to the hooks unchanged.
- `live_from` names the one release this update may replace live. A device
  running any other release reboots into it as usual. This keeps the live path
  to a single, tested transition.

Both are covered by the manifest signature. `atom-sign manifest` sets them with
`--apply-class` and `--live-from`; a release without them is reboot only.

## When a candidate is eligible

The staged candidate can be applied live only when all of these hold:

- its kept manifest still verifies against the root key;
- `live_from` matches the running release and the running root is the installed one;
- `kernel_release` names the running kernel, and the new root ships modules for it;
- the running root is a verified erofs image with an `/etc` overlay.

`updated apply-live --check` and the `live` field of the daemon's status report
the result and, when the answer is no, why.

## The switch

The new root is opened through dm-verity against the signed root hash, mounted
read-only, and checked before anything moves. Then every mount of the running
root (`/var`, `/run`, `/dev`, `/proc`, `/sys`, `/home`, `/boot` and anything below
them) is moved onto the new root, a fresh `/etc` overlay is made over the new
image with the same upper layer, and `pivot_root` makes it the root of every
process in the init mount namespace.

Both images must ship the empty directory `/usr/lib/atomloops/live`. The new root
is prepared under it, and the previous root is parked on it while the switch is
on trial.

## Hooks

Executables in `/usr/lib/atomloops/live.d` run with the phase as their argument
and `ATOM_APPLY_CLASS`, `ATOM_FROM`, `ATOM_TO` and `ATOM_OLD_ROOT` in the
environment:

| Phase | Runs from | Purpose |
| --- | --- | --- |
| `switched` | new root | restart what the update touched |
| `health` | new root | confirm the system works; a failure rolls back |
| `rolledback` | previous root | undo what `switched` did |
| `committed` | new root | the switch is final |

## Trial, rollback and commit

Until the switch is committed, the previous root is still mounted, and a failing
hook returns every process to it and releases the new image. Nothing is written
to the deployment WAL.

Commit records the switch as a good boot of the candidate, exactly as a reboot
into it would. The candidate becomes current, and it is promoted once it reaches
the stable threshold. Until then the next boot still tries it on the trial
budget, so the previous image stays the fallback. The previous root is detached;
its verity mapping and loop devices are released when the last process still
running from it exits.

Because `/proc/cmdline` keeps describing the booted image, the identity of the
running root is recorded in `/run/atomloops/live/identity` for the rest of the
boot.

## Measurement

Each committed switch is written to the sealed log (`live-applied`, or
`live-rollback` when a trial fails) and, when the system names a PCR with
`--live-pcr`, extended into the TPM as the SHA-256 of the class, both releases
and both root hashes.
