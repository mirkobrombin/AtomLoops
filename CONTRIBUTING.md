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

## Device- and environment-specific code

Code that exists only because of a specific device, architecture, firmware or environment must be marked on the line above it:

```
DEVICE-FIX(<scope>): <what breaks without this>
```

- `<scope>` is one of: `arm64`, `x86_64`, `uno-q`, `jetson`, `msm`, `nvidia`, `intel`, `amd`, `no-tpm`, `vm`, `u-boot`, `uefi`, `gs201`. A new scope is added to this list in the same pull request that first uses it.
- The text states what fails on that device without the code, not what the code does.
- Use the comment syntax of the file's language.
- This covers driver names, hardware probes, architecture constants, firmware quirks, boot-chain differences and anything gated on a specific environment.
- A pull request that adds or changes such code without the marker is not merged.
- `git grep -n "DEVICE-FIX("` lists every marker in the repository.
