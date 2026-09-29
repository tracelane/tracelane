<!-- tracelane:classification: PUBLIC -->
# AI Disclosure

Tracelane is built with significant AI assistance. We are transparent about this.

## How we build

**Primary tool:** [Claude Code](https://claude.ai/code) (Anthropic) — used for
architecture planning, code generation, documentation, and autonomous task
execution under founder direction.

**Model:** the main session runs Claude Opus 5. Delegated subagents run the
models pinned per-agent in the canonical repository — claude-sonnet-4-6 (implementer tasks),
claude-opus-4-7 (security review), claude-haiku-4-5-20251001 (PR descriptions
and changelogs).

Model IDs change as new ones ship, and a hand-maintained list here drifts. The
**authoritative per-commit record is the `Co-Authored-By` trailer on each
commit** — `git log --format='%(trailers:key=Co-Authored-By,valueonly)'` shows
exactly which model assisted which change.

**Provenance:** Commits are reviewed by the maintainer before they are published.
AI-generated code is intended to be merged only with human sign-off.
Commits co-authored by Claude include:

```
Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
```

## What this means for you

- **Code quality:** AI-assisted code is reviewed against the same standards as
  human-written code. CI gates (clippy, biome, ruff, eval suite) enforce quality
  automatically.
- **Security:** Security-critical paths get an additional review pass.
- **Reproducibility:** Architectural decisions are documented as ADRs, summarised at
  <https://docs.tracelane.dev/decisions>
  so future maintainers understand the reasoning.
- **License:** AI-generated code is original work contributed by the founder.
  Our policy is not to knowingly copy GPL, ELv2, or other restrictively-licensed code.

## Why we're transparent

We believe AI-assisted development is the future of solo-founder infrastructure
companies. We'd rather be honest about it than pretend otherwise. Production code is
reviewed by a human maintainer before release.

---

*Last updated: 2026-04-29*
