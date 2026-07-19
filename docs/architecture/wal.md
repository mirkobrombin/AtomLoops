# The deployment WAL

The state that ties deployment and boot together is a small write-ahead log,
`deployment.json`. It is the single source of truth for which image is current,
which is a candidate, which is the fallback, and how many boot attempts remain.

## Why a write-ahead log

Deployment and boot are separated in time and can be interrupted by a crash or a
power cut at any moment. A write-ahead log makes the state transitions
crash-durable: the log records the intended next state before it is acted on, so a
boot that starts mid-transition can always reconstruct a consistent view instead
of finding a half-written slot.

## What it records

The log holds the deployment state the daemon and the initramfs both read:

- **current** the confirmed, running image.
- **pending / candidate** an image staged by deployment, not yet confirmed.
- **rollback** the last known good image to fall back to.
- **boot attempts** the remaining tries for the current candidate.
- **verity hash** the target root's verity hash, recorded at staging for the
  boot-time integrity check.

## Crash-durable writes

The boot-state is written crash-durably: the daemon writes to a unique temporary
file and swaps it into place, so a crash never leaves a torn, half-written state
file. A boot that reads the log always sees either the old state or the new one,
never a mix.

## Only the running candidate is promoted

Confirmation is conservative. The daemon confirms a candidate only when the
running system actually is that candidate, so it never promotes an image that the
loader silently fell back away from. On a stable boot it also reconciles the
hardware anti-rollback counter with the promoted log, closing the gap a crash
could otherwise leave between the two.
