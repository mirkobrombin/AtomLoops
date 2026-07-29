# Contributing to Atom Loops

Thanks for your interest in contributing!

## Quick Start

```bash
git clone https://github.com/mirkobrombin/AtomLoops
cd atomloops
go build ./...
go test ./...
# the UEFI loader (needs zig 0.16):
cd loader && sh build.sh
```

## Guidelines

- Keep changes additive and tested. This code gates system updates and boot, so
  prefer small, verifiable commits, and never weaken a signature or hash check
  for convenience.
- Match the surrounding style. Comments explain WHY, not WHAT.
- By submitting a contribution you agree to the [CLA](CLA.md).

## License

GPL-3.0-only.
