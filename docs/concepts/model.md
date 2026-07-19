# The model

Atom Loops treats an operating-system update as a single transaction over a
**whole, signed image**, not as a set of package changes applied on top of each
other. This page explains the model and the boundaries it sets for itself.

## One transaction: download, verify, switch

An update has three logical steps, and either all of them take effect or none do:

1. **Download** the new image (only the parts that changed).
2. **Verify** it end to end against a signing chain before it is trusted.
3. **Switch** to it, atomically, at the next boot.

There is no intermediate state where part of the system is new and part is old. A
failure at any step leaves the running system exactly as it was.

## Immutable system, separate data

The system root is immutable by design. It carries no editable state and is
replaced whole on each update, which is what makes an update reproducible: what
runs is exactly what was built and signed. Your data and local state live
separately, so an update never has to merge system files into a modified tree.

## Slots

Atom Loops keeps the system in slots and switches between them. A new image is
staged into the inactive slot; the active slot keeps running until the switch is
committed at boot. If the new slot does not boot cleanly, the old slot is still
intact to fall back to.

## What Atom Loops is not

The scope is deliberately narrow. Atom Loops does atomic deployment of the OS and
little else.

- **Not a package manager.** It does not install or customize packages on the
  device. It ships the image as built.
- **Not tied to a content-addressed store.** Object-store systems add a checkout
  step and a tight coupling to their distribution tooling. Atom Loops works on
  plain images.
- **Not dependent on container images.** It consumes a finished update image, not
  OCI layers, so it needs no container engine.
- **Not demanding on partitions.** Beyond a small ESP, it does not require a fixed
  A/B partition layout with two full copies of the OS.

It is also indifferent to how the image was built. Whoever produces the update can
use any tools they like; Atom Loops only consumes the final, signed artifact. See
[Integrating Atom Loops](../integration.md) for what an image has to provide.
