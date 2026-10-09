<!-- tracelane:classification: PUBLIC -->
# AI Disclosure

Tracelane is built with significant AI assistance. We are transparent about this.

## How we build

Coding agents assist with architecture planning, code generation, documentation,
and tasks under maintainer direction. Tools and models vary by change.

Model IDs change as new ones ship, and a hand-maintained list here drifts. The
`Co-Authored-By` trailer on a commit can identify an assisting model. Run
`git log --format='%(trailers:key=Co-Authored-By,valueonly)'` to see the trailers
that were supplied; absence of one is not proof of no AI assistance.

**Provenance:** Commits are reviewed by the maintainer before they are published.
AI-generated code is intended to be merged only with human sign-off.
Some commits co-authored by Claude include:

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
