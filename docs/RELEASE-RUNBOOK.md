# Atom Loops release runbook

How to cut an OTA update and how a device installs it safely. Covers the two
tools: `atom-sign` (release side, builds + signs) and `atomd` (device side,
fetches + verifies + stages + promotes). Nothing here needs a network service you
do not control: the device only pulls signed, hashed artifacts over plain HTTP(S).

## The pipeline at a glance

```
RELEASE SIDE (your build host)                 DEVICE SIDE (atomd)
  atom-sign keygen        one-time root key      atomd run  (greenboot + poll)
  build rootfs + kernelcache                       -> fetch manifest (httpx, retried)
  atom-sign manifest  ->  manifest.json            -> verify Ed25519 signature
  atom-sign sign      ->  manifest.json.sig        -> fetch artifacts, verify SHA256
  publish over HTTP(S)                             -> refuse downgrades (anti-rollback)
                                                    -> stage into -next slots, mark WAL pending
                                                   reboot -> initramfs tries the candidate
                                                    -> health checks pass N boots -> promote
                                                    -> arm the monotonic anti-rollback counter
                                                    -> fail -> auto rollback / recovery
```

## 0. One-time: the root of trust

Generate the root keypair once. The PUBLIC key is the single trust anchor for
BOTH the loader (kernelcache self-verify) and the daemon (manifest verify); the
PRIVATE key signs releases and must never leave the build host / never be
committed.

```
atom-sign keygen --priv root.key --pub root.pub
```

- Put `root.pub` where the daemon reads it (default `/etc/atom/root.pub`) AND at
  `loader/src/root.pub`, then rebuild the loader (`loader/build.sh`). One key,
  both consumers.
- Keep `root.key` offline. `*.key` is gitignored; do not publish it.

Provision the device WAL at first install (records the initial version as its own
last_known_good):

```
atomd init --wal /boot/rootfs/deployment.json --device-id <id> v1
```

## 1. Cut a release

Build the two artifacts your image pipeline produces: the rootfs image and the
kernelcache (UKI). Then describe and sign them.

```
# 1. build rootfs.erofs and kernelcache.efi (your buildroot/package step)

# 2. write the manifest: hashes are computed from the files, urls are where the
#    device will fetch them from.
atom-sign manifest \
  --version v2 --min-version v1 \
  --rootfs rootfs.erofs   --rootfs-url https://updates.example/v2/rootfs.erofs \
  --kernelcache kernelcache.efi --kc-url https://updates.example/v2/kernelcache.efi \
  --out manifest.json

# 3. sign it (writes manifest.json.sig, a detached Ed25519 signature)
atom-sign sign --priv root.key --manifest manifest.json

# 4. publish rootfs.erofs, kernelcache.efi, manifest.json, manifest.json.sig
#    on any static HTTP(S) host.
```

`min_version` is the anti-rollback floor the update declares. The daemon also
refuses any manifest whose version is below the version already installed.

## 2. The device installs it

Run the daemon as a service under sinit. It confirms the current boot at startup
(greenboot) and, if a manifest URL is configured, polls for updates on a schedule
and stages any it verifies.

```
atomd run \
  --wal /boot/rootfs/deployment.json \
  --health-dir /etc/atom/health.d \
  --manifest https://updates.example/latest/manifest.json \
  --pubkey /etc/atom/root.pub \
  --cron "0 * * * *" \
  --counter /var/lib/atom/anti-rollback \
  --audit /var/log/atom/history.jsonl \
  --rootfs-dir /boot/rootfs --esp-dir /boot/efi/EFI/atom
```

Or stage a specific manifest on demand:

```
atomd stage --manifest https://updates.example/v2/manifest.json --pubkey /etc/atom/root.pub
```

What staging guarantees: the manifest signature is checked, each artifact's
SHA256 is checked, and a downgrade is refused, BEFORE anything is written to the
WAL. If any byte fails to download or verify, the WAL is untouched and the device
keeps running the current version. Only a fully verified candidate is marked
`pending` in the WAL, into the `-next` slots.

## 3. Promotion, rollback, recovery

- On reboot the initramfs tries the pending candidate and drains its boot budget.
- Once up, greenboot runs the health checks in `--health-dir` (every executable
  must exit 0; an empty/missing dir counts as healthy). This happens
  automatically inside `atomd run`, or on demand:

  ```
  atomd boot-success --wal ... --health-dir /etc/atom/health.d --counter /var/lib/atom/anti-rollback
  ```

  After the candidate stabilizes over `stable_threshold` good boots it is promoted
  to `last_known_good`, and only THEN is the monotonic anti-rollback counter
  advanced (a faulty update never moves the floor).

- Hardware anti-rollback: point the daemon at a TPM2/RPMB counter instead of the
  software file with `--counter-read '<cmd>'` and `--counter-advance '<cmd>'`
  (the advance command receives the target in `$ATOM_COUNTER`).

- Manual rollback to last_known_good:

  ```
  atomd rollback --wal /boot/rootfs/deployment.json
  ```

- Recovery mode (served from the independent recovery image):

  ```
  atomd recover --wal ... --addr :7654 --audit /var/log/atom/history.jsonl
  #  GET  /status   -> the WAL state
  #  POST /rollback -> return to last_known_good, no network needed
  #  GET  /history  -> the update audit log
  ```

- Inspect state any time:

  ```
  atomd status --wal /boot/rootfs/deployment.json
  ```

## Trust model, in one paragraph

Every update is a signed manifest (detached Ed25519, verified against the embedded
root public key) describing artifacts pinned by SHA256; the daemon verifies the
signature and every hash before staging and refuses downgrades; the loader
verifies the kernelcache against the same root key and measures it into a TPM PCR;
after a candidate proves healthy it promotes and advances a monotonic
(software or TPM2/RPMB) anti-rollback counter; a spent boot budget rolls back
automatically, and recovery mode restores from last_known_good with no network.
No step trusts an artifact it has not verified.
