# Contributing to Vectis Mail

Thanks for your interest in contributing. Vectis Mail is a commercial product
released under a **source-available** licence
([Business Source License 1.1](LICENSE)), so contribution terms are a little
different from a typical OSS project. Please read this document before
opening a pull request.

## TL;DR

- **Bug reports:** very welcome — open a GitHub issue with reproduction steps.
- **Security disclosures:** **do not** open a public issue. Email
  `security@vectismail.com` (or see [`SECURITY.md`](SECURITY.md)).
- **Documentation fixes:** PRs welcome with a DCO sign-off (`Signed-off-by:`).
- **Code contributions:** open an issue first to discuss approach. PRs must
  carry DCO sign-off on every commit and accept the inbound contributor terms
  below.

## Inbound contributor terms

By submitting a contribution (code, documentation, configuration, tests, or
any other content) to this repository, you certify that:

1. You have the right to submit the contribution.
2. You agree your contribution is licensed under the same
   [Business Source License 1.1](LICENSE) as the rest of the codebase,
   with the same Change License (Apache 2.0) and Change Date.
3. You grant Veltara Works a perpetual, worldwide, royalty-free, irrevocable
   licence to use, modify, sublicense, and relicense your contribution as
   part of the project, including under future commercial licences offered
   by Veltara Works to subscribers.
4. You retain copyright in your contribution; this is a licence, not an
   assignment.

These terms are similar to the model used by Sentry, Cal.com, and other
source-available projects with commercial tiers.

## DCO — Developer Certificate of Origin

Every commit in a pull request must be signed off, certifying the contributor
has the right to submit it under the terms above. To sign off, add a
`Signed-off-by:` trailer to your commit message:

```
fix: handle empty SPF record without panicking

Signed-off-by: Your Name <you@example.com>
```

The easiest way is to use the `-s` flag with `git commit`:

```bash
git commit -s -m "fix: handle empty SPF record without panicking"
```

The full DCO text is at [developercertificate.org](https://developercertificate.org/)
and reproduced below for reference:

```
By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is licensed under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part by
    me, under the same open source license (unless I am permitted
    to submit under a different license), as indicated in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified it.

(d) I understand and agree that this project and the contribution are
    public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## What kinds of contributions are most useful

- **Reproductions of bugs you've hit on Starter tier installs.** A clear
  repro is half the fix.
- **Documentation improvements** — typos, clearer wording, missing edge
  cases in install / DNS / deliverability guides.
- **Adapters and integrations** — if you've written a useful third-party
  integration (e.g. a Terraform module, Ansible role, Kubernetes operator),
  open an issue to discuss whether it belongs in this repo or as a
  companion repo.

## What kinds of contributions we'll usually decline

- **Large architectural changes** without prior discussion. The architecture
  is documented in `docs/architecture/`; please open an issue or a discussion
  before opening a PR that changes the shape.
- **New top-level dependencies** without prior discussion.
- **Features that exist behind the Pro tier** — please don't open PRs that
  add Pro features to the Starter tier; this is contrary to the project's
  commercial model.

## Development setup

See [`README.md`](README.md) for build instructions. Quick path:

```bash
git clone https://github.com/Veltara-Works/vectis.git
cd vectis
go build ./cmd/vectis
cd web && npm install && npm run build
```

Run the test suite:

```bash
go test ./...
```

Integration tests are guarded by `//go:build integration` and require a
running Postgres + Valkey; see `internal/repository/` for the conventions.

## Coding style

- **Go:** use `gofmt` (or `goimports`) before committing. Prefer the standard
  library; avoid framework reach. Errors carry context (`fmt.Errorf("doing
  X: %w", err)`).
- **TypeScript / React:** follow the project's existing patterns; we use
  TypeScript strict mode and don't take new front-end dependencies lightly.
- **Commits:** present-tense, concise, prefixed (`fix:`, `feat:`, `docs:`,
  `refactor:`, `test:`, `chore:`).

## Issue templates

When opening an issue:

- **Bug reports:** include Vectis version (`vectis version`), OS, Docker
  version, exact command + output, and `vectis health` output if reachable.
- **Feature requests:** describe the use case, not just the implementation.
  Pro / Enterprise feature requests will be routed to the product backlog,
  not the open issue tracker.

## Contact

- **Bug reports:** [GitHub Issues](https://github.com/Veltara-Works/vectis/issues)
- **Questions, ideas, show-and-tell:** [GitHub Discussions](https://github.com/Veltara-Works/vectis/discussions)
- **Security:** `security@vectismail.com` (see [`SECURITY.md`](SECURITY.md))
- **Licensing / commercial:** `licensing@veltaraworks.com`
- **General:** `hello@vectismail.com`
