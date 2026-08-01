# Changelog

All notable changes to `@tracelanedev/cli` (`tlane`) are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.2.3] - 2026-08-01

### Changed
- Version-only release. No source changes since 0.2.2 — re-cut because the 0.2.2
  tag published this package to npm but produced no signed release artifacts
  (the release job could not resolve one of its pinned actions). 0.2.3 is the
  same code from a release that carries a GitHub Release, Cosign signatures, an
  SBOM and SLSA provenance.

## [0.2.2] - 2026-08-01

### Fixed
- **`tlane init` no longer defaults to a hostname that does not exist.** The
  `--endpoint` default was `https://ingest.tracelane.dev`, which has never
  resolved (NXDOMAIN), so `tlane init` scaffolded a `tracelane.config.json`
  pointing at nothing. It now defaults to `http://localhost:4318` — an OTLP
  receiver you run. Tracelane Cloud exposes no public OTLP ingress; on Cloud,
  point an OpenAI-compatible client at `https://gateway.tracelane.dev/v1` and
  the gateway captures the trace.
- **`tlane init` no longer has a check-then-write race.** It used `existsSync`
  followed by `writeFileSync`; anything created between the two — including a
  symlink pointing somewhere you did not intend to write — was overwritten
  *without* `--force`. The write is now a single exclusive-create (`wx`) syscall,
  so the refusal is enforced by the write itself and the window cannot exist.
  `--force` still overwrites. Regression test asserts an existing config stays
  byte-identical. (CodeQL `js/file-system-race`)
- **`tlane prompt diff` pins its temp filenames.** The prompt name and the
  `--from-env` / `--to-env` values are free-form input that was interpolated into
  a path, so a `../` escaped the temp directory. Both files are now pinned inside
  the freshly created directory with `path.basename()`. (CodeQL
  `js/http-to-file-access`)

## [0.2.1] - 2026-07-25

### Fixed
- **`tlane verify` inherits the ADR-070 windowed-verify fix.** The CLI embeds
  `@tracelanedev/audit-verifier` (`workspace:*` → pinned at publish time), so
  0.2.1 ships the 0.2.1 verifier: a retention-windowed ledger whose genesis has
  aged out now verifies **GREEN** when rooted at a public Rekor anchor inside the
  window, instead of the prior false **RED** (`seq_out_of_order`). A windowed
  ledger with no in-window anchor still exits non-zero (`unrooted_window`). No
  CLI-surface changes; the dependency refresh is the whole of this release.
