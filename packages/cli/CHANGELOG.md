<!-- tracelane:classification: PUBLIC -->
# Changelog

All notable changes to `@tracelanedev/cli` (`tlane`) are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.3.0] - 2026-09-01

### Security
- **`tlane verify` fails closed when anchors could not be checked.** A ledger carrying
  anchor records verified without a trusted tenant key reported a pass, printing
  `signatures_valid: true` over an anchor that was never checked — `signatures_valid`
  is vacuously true in chain-only mode. The status is now `INCOMPLETE` and the command
  exits non-zero, so a verification that could not run can no longer read as one that
  passed. Requires `@tracelanedev/audit-verifier` 0.3.0, which this release depends on.

### Added
- **`tlane eval`** — runs a prompt evaluation against a dataset and fails a build when
  the mean score falls below a floor you set (`--threshold`). Errored cases are excluded
  from the score and bounded separately by `--max-error-rate`, so a provider `429`
  cannot be mistaken for a quality drop. Exit codes are distinct by design: `0` pass,
  `1` below the floor, `2` usage error, `3` could not evaluate.

### Added
- **`tlane init` now scaffolds the `.env`, installs the SDK, and wires the
  frameworks it detects** — previously it wrote `tracelane.config.json` and
  printed install hints, and nothing else.
  - `.env` gets `TRACELANE_API_KEY` and `TRACELANE_GATEWAY_URL`. The merge is
    append-only: a value you already set is never rewritten, `--force`
    included. If a `.gitignore` exists and does not already cover `.env`, the
    entry is added, because the file now holds a key.
  - Frameworks are detected from `package.json` (Node) and
    `pyproject.toml` / `requirements.txt` / `Pipfile` (Python), then written
    into a bootstrap — `tracelane.ts`, `tracelane.mjs` or `tracelane_init.py`.
    A polyglot repo gets both. On Python the bootstrap emits
    `init(..., auto_instrument=True)`, which wraps installed `openai`,
    `anthropic`, `litellm` and `claude_code` with no further edit. Every other
    adapter — including all of the TypeScript ones — wraps an object only you
    can construct, so the bootstrap imports the right `instrument*` function and
    puts the exact call beside it. The TypeScript SDK has no zero-config
    patching; `autoInstrument()` throws by design and is not implemented.
  - The SDK is installed with the package manager your lockfile names (`pnpm`,
    `yarn`, `bun`, `npm`, `uv`, `poetry`, `pipenv`, or `python3 -m pip`). A
    failed install exits non-zero and prints the command to re-run; the
    scaffolded files are left in place.
  - New flags: `--no-env`, `--no-instrument`, `--no-install`. `--force` now also
    governs the bootstrap, which is otherwise never overwritten.

### Fixed
- `tlane init` does not write `TRACELANE_ENDPOINT` into `.env`. `tlane replay`
  reads that variable as a **gateway** base URL, so scaffolding the OTLP
  receiver URL under that name would have pointed replay at the wrong port. The
  OTLP endpoint stays in `tracelane.config.json` and is inlined into the
  generated bootstrap.

## [0.2.3] - 2026-08-01

### Changed
- Version-only release. No source changes since 0.2.2 — re-cut because the 0.2.2
  tag published this package to npm but produced no signed release artifacts
  (the release job could not resolve one of its pinned actions). 0.2.3 is the
  same code from a release that carries a GitHub Release, Cosign signatures and an
  SBOM. A verified SLSA Level 3 attestation is not claimed - the
  slsa-github-generator final job fails even on successful releases.

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
- **`tlane verify` inherits the windowed-verify fix.** The CLI embeds
  `@tracelanedev/audit-verifier` (`workspace:*` → pinned at publish time), so
  0.2.1 ships the 0.2.1 verifier: a retention-windowed ledger whose genesis has
  aged out now verifies **GREEN** when rooted at a public Rekor anchor inside the
  window, instead of the prior false **RED** (`seq_out_of_order`). A windowed
  ledger with no in-window anchor still exits non-zero (`unrooted_window`). No
  CLI-surface changes; the dependency refresh is the whole of this release.
