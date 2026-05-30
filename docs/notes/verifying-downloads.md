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
