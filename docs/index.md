# Atom Loops

<p align="center">
  <img src="img/logo.png" alt="Atom Loops" width="120">
</p>

Atom Loops is an open-source system for **atomic and reproducible deployment of the
operating system** on embedded and desktop Linux devices. An update is one
transaction: download, verify, switch, with automatic rollback on boot failure.

It is not a Linux distribution and not a package manager. It consumes a finished
system image and owns only the deploy and rollback lifecycle. It needs no
container engine, no registry, and no dedicated partition layout beyond an ESP.

!!! warning "Status"
    Under active development, not ready for production. The first integration
    target is [Sinty OS](https://github.com/singularityos-lab), where the code is
    exercised end to end. Only x86_64 (UEFI) is validated so far. See the
    [roadmap](roadmap.md) for what is implemented and what is not.

## What it guarantees

- **Atomic.** An update is either fully applied or not at all. There is no
  half-updated state.
- **Verifiable.** Every image is signed and checked end to end before it is
  trusted. Trust is the signature, not the transport.
- **Reversible.** If a new image fails to boot, the boot chain returns to the last
  good image on its own.
- **Reproducible.** The system ships as a whole, signed image. What runs is exactly
  what was built, not the result of changes layered on top.

## How it works, in one paragraph

A background daemon prepares the update while the system runs: it checks the
revocation list, verifies the signed manifest, downloads only what changed,
re-verifies the artifacts and stages them. Nothing is switched yet. The switch
happens at the next boot, and the boot decides whether it holds: the initramfs
checks the anti-rollback counter, reads the write-ahead log, sets up dm-verity and
swaps the slots. If the attempt counter runs out the device falls back or enters
recovery. Only after enough good boots is the new image promoted.

## Where to go next

- New here? Start with [The model](concepts/model.md).
- Want the flow end to end? [Deployment lifecycle](concepts/deployment.md) and
  [Boot lifecycle](concepts/boot.md).
- Shipping your own OS on it? [Integrating Atom Loops](integration.md).
- Curious about the guarantees? [Trust model](security/trust-model.md).

## License

GPL-3.0. Source on [GitHub](https://github.com/mirkobrombin/AtomLoops).
