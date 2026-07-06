# Verifying Vectis downloads

Every Vectis release signs its downloadable artifacts with [cosign](https://docs.sigstore.dev/)
using **keyless / Sigstore OIDC** signing. There is no long-lived signing key:
each signature is bound to the GitHub Actions identity of the release workflow
and recorded in the public Rekor transparency log.

Signed artifacts (each has a companion `.cosign.bundle`):

| Artifact | URL (per version) |
|---|---|
| Installer | `https://dl.vectismail.com/<version>/install.sh` |
| Binary | `https://dl.vectismail.com/<version>/vectis-linux-amd64` |
| Checksum | `https://dl.vectismail.com/<version>/vectis-linux-amd64.sha256` |

`<version>` is a release tag (e.g. `v0.1.17`) or `latest`. The same files are
attached to each [GitHub Release](https://github.com/Veltara-Works/vectis/releases).

The eight container images are signed the same way. Their signatures live in the
registry next to the image (no separate bundle file) and are verified with
`cosign verify`:

| Image | Reference (per version) |
|---|---|
| api | `ghcr.io/veltara-works/vectis-api:<version>` |
| orchestrator | `ghcr.io/veltara-works/vectis-orchestrator:<version>` |
| postfix | `ghcr.io/veltara-works/vectis-postfix:<version>` |
| dovecot | `ghcr.io/veltara-works/vectis-dovecot:<version>` |
| rspamd | `ghcr.io/veltara-works/vectis-rspamd:<version>` |
| clamav | `ghcr.io/veltara-works/vectis-clamav:<version>` |
| cert-extractor | `ghcr.io/veltara-works/vectis-cert-extractor:<version>` |
| webmail | `ghcr.io/veltara-works/vectis-webmail:<version>` |

## Trust anchor

cosign verification must assert **who** signed the artifact:

- **Certificate identity** (the release workflow, on any tag):
  `^https://github.com/Veltara-Works/vectis/.github/workflows/release.yml@refs/tags/`
- **OIDC issuer:** `https://token.actions.githubusercontent.com`

## Verify the binary

```bash
BASE=https://dl.vectismail.com/latest      # or a pinned version, e.g. /v0.1.17

curl -fsSLO "$BASE/vectis-linux-amd64"
curl -fsSLO "$BASE/vectis-linux-amd64.cosign.bundle"

cosign verify-blob \
  --bundle vectis-linux-amd64.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/Veltara-Works/vectis/.github/workflows/release.yml@refs/tags/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  vectis-linux-amd64
```

A successful run prints `Verified OK`.

## Offline release signature (Ed25519)

In addition to keyless cosign, the binary and each release-channel manifest carry
a companion `.ed25519` detached signature made with an **offline** Ed25519 release
key. Its public half is compiled into every Vectis binary, so `vectis update`
verifies this signature **in-process** — with no external tool — before applying a
self-update, and the orchestrator verifies the release manifest the same way
before acting on it. This is the gate that defends against a compromised download
origin (`dl.vectismail.com` / DNS / a TLS-strip MITM): such an attacker can serve
bytes but cannot forge a signature without the offline key.

The release manifest also pins each vectis service image to its immutable
`sha256:` digest (an `images` map keyed by service name). Because the whole
manifest is Ed25519-signed, those digests are authenticated too — so the
orchestrator pins the compose `image:` line to the canonical
`ghcr.io/veltara-works/vectis-<svc>:<tag>@sha256:<digest>` form (exactly the bytes
this release published) instead of trusting whatever the mutable `:tag` resolves
to at pull time. The tag is kept alongside the digest deliberately: docker records
`.Config.Image` verbatim, so keeping `:tag@sha256:` means `docker inspect` and the
running-vs-declared diff stay readable rather than showing a bare digest. A
manifest without an `images` map (a pre-REL-3 release or a self-hosted mirror)
degrades to a tag-only pin and the orchestrator warns.

The manifest likewise pins the host CLI binary via a `binary_sha256` field (a bare
lowercase sha256 hex of the published `vectis-linux-amd64`). During a host
self-update, `vectis update` checks the binary it just downloaded against this
**signed** digest — not only the same-origin `.sha256` and the per-binary
`.ed25519`. The per-binary signature authenticates the bytes but carries no
version metadata, so on its own it can't tell a *current* release apart from an
*older* one that was also validly signed; a compromised origin could replay the
genuine current manifest (newest tag, passing anti-rollback) while serving an
older still-signed binary to force a downgrade. Binding the bytes to the signed
manifest that named the tag closes that (REL-1). A manifest without a
`binary_sha256` (a pre-REL-1 release or a self-hosted mirror) degrades to the
Ed25519-signature-only gate.

## Host-side image provenance (cosign, automatic)

The digest pin above guarantees the orchestrator runs *exactly the bytes the
signed manifest names*. On top of that, during every update the orchestrator
verifies those bytes were **built and signed by our release workflow** — the same
keyless cosign check documented above, run automatically on the host. After
pulling the new images and before recreating any container (Apply phase 4.1.5),
it runs a **digest-pinned cosign container** to `cosign verify` each
`vectis-<svc>@sha256:<digest>` against the release-workflow identity
(`…/.github/workflows/release.yml@refs/tags/…`) and the GitHub Actions OIDC
issuer. No cosign install on the host is required — the pinned container carries
it (`ghcr.io/sigstore/cosign/cosign`, itself digest-pinned so the verifier can't
be swapped via a floating tag).

This layer is **defence-in-depth and best-effort**: if the Sigstore transparency
log / CA is unreachable (an air-gapped or DR host, or a Rekor/Fulcio outage), the
verify is logged as a warning and the update **proceeds** — the Ed25519-signed
digest pin is the hard integrity guarantee and must not be gated on the
availability of an external service. A failed or unverifiable signature never
rolls back an otherwise-healthy update; it surfaces in the orchestrator log.
Only `vectis-*` images are checked — third-party base images (postgres, traefik,
valkey, …) aren't signed by our workflow and are integrity-pinned by digest in
the compose template instead.

The public key is `GYnHjxJS1l3QQmlZ9+36BuNwxtHh758C0X8jfy9IaN8=` (the value
compiled into `internal/releasesign.PublicKeyB64`). **If the release key is ever
rotated, update this value too** — the per-release notes auto-extract the key from
source, but this static doc does not, so it would otherwise go stale and point
users at the wrong key. To verify a downloaded binary manually:

```bash
BASE=https://dl.vectismail.com/latest      # or a pinned version
curl -fsSLO "$BASE/vectis-linux-amd64"
curl -fsSLO "$BASE/vectis-linux-amd64.ed25519"

python3 - <<'PY'
import base64, nacl.signing  # pip install pynacl
pub = base64.b64decode('GYnHjxJS1l3QQmlZ9+36BuNwxtHh758C0X8jfy9IaN8=')
sig = base64.b64decode(open('vectis-linux-amd64.ed25519').read().strip())
nacl.signing.VerifyKey(pub).verify(open('vectis-linux-amd64', 'rb').read(), sig)
print('OK: Ed25519 signature valid')
PY
```

Unlike cosign (transport/provenance), this signature is the mandatory,
fail-closed check on the auto-update path — a missing or invalid `.ed25519`
refuses the update rather than falling back to the SHA256 (which only proves
transport integrity from the same origin).

## Verify a container image

Each image is signed by its immutable manifest digest, so the signature is
pinned to exact bytes and covers every tag that points at that digest (e.g.
`:<version>` and `:latest`). Verify by tag or by digest — cosign resolves the
tag to the digest before checking:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/Veltara-Works/vectis/.github/workflows/release.yml@refs/tags/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/veltara-works/vectis-api:latest      # or a pinned version / @sha256:digest
```

A successful run prints `Verified OK` and the signature's certificate details.
Repeat for each of the eight service images listed above.

## Verify the installer before running it

`curl … | sudo bash` cannot verify itself. To check the installer first:

```bash
BASE=https://dl.vectismail.com/latest

curl -fsSLO "$BASE/install.sh"
curl -fsSLO "$BASE/install.sh.cosign.bundle"

cosign verify-blob \
  --bundle install.sh.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/Veltara-Works/vectis/.github/workflows/release.yml@refs/tags/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  install.sh

# Only then:
sudo bash install.sh
```

## Verification inside install.sh

The installer also verifies the binary's signature automatically **when cosign
is present on the host**:

- `cosign` installed → the installer verifies the binary bundle and **aborts**
  if the signature does not match. (This is in addition to the always-enforced
  SHA256 checksum.)
- `cosign` absent → the installer notes it and continues on the SHA256 checksum.

Environment toggles:

| Variable | Effect |
|---|---|
| `VECTIS_REQUIRE_COSIGN=1` | Fail the install if cosign is missing or no bundle is published. |
| `VECTIS_SKIP_COSIGN=1` | Skip cosign verification entirely (SHA256 still enforced). |

Example — hard-require signature verification:

```bash
curl -fsSLO https://dl.vectismail.com/latest/install.sh
VECTIS_REQUIRE_COSIGN=1 sudo -E bash install.sh
```

## Installing cosign

See the [Sigstore installation docs](https://docs.sigstore.dev/system_config/installation/).
On most systems:

```bash
go install github.com/sigstore/cosign/v3/cmd/cosign@latest
# or download a release binary from https://github.com/sigstore/cosign/releases
```
