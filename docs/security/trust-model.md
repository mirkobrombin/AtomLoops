# Trust model

The core rule is simple: **trust is the signature, not the transport.** An image
fetched over any host or link, including a plain static file host, is authenticated
by its signature and hashes, not by where it came from. A forged image is rejected
regardless of the network that served it.

## Two-level keys

Atom Loops uses a two-level key chain so the key that signs day-to-day updates is
never the key that anchors trust.

- **Root key (cold).** The root is kept offline. It signs two things: a
  short-lived **signing certificate** and a **revocation list**. It does not sign
  updates directly.
- **Signing key (operational).** The signing key signs the **update manifests**.
  It is vouched for by a certificate under the root, and it can be revoked by the
  root without rotating the root itself.

This separation means a compromised signing key is contained: the root revokes its
certificate, and devices reject anything it signed from then on, without the root
ever going online to sign an update.

## Verification order

The daemon verifies in a fixed order, cheapest and most decisive first:

1. **Revocation.** Check the root-signed revocation list. A revoked signing
   certificate stops here.
2. **Certificate.** Check the signing certificate against the root key.
3. **Manifest.** Check the update manifest against the signing key the certificate
   vouches for.
4. **Artifacts.** Check each downloaded artifact by SHA256 against the manifest.

Only an update that passes all four is allowed near the staging slot. The same
chain runs on the boot side before an image is allowed to run, so trust does not
depend on the deployment daemon being intact.

## Why the transport can be untrusted

Because verification is anchored in the signature chain, the delivery mechanism
carries no trust. Updates can be served from GitHub Releases, a CDN, or any static
host, and a hostile or man-in-the-middle host cannot substitute an image: it would
fail the manifest or artifact check. This is what lets the recovery path
re-download and reinstall a system over an untrusted network.
