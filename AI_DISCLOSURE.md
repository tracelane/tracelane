# AI Disclosure

Tracelane is built with significant AI assistance. We are transparent about this.

## How we build

**Primary tool:** [Claude Code](https://claude.ai/code) (Anthropic) — used for
architecture planning, code generation, documentation, and autonomous task
execution under founder direction.

**Model:** claude-sonnet-4-6 (main session and implementer tasks),
claude-opus-4-7 (security review), claude-haiku-4-5-20251001 (PR descriptions
and changelogs).

**Provenance:** Every commit in this repository was reviewed and approved by a
human (the founder). AI-generated code is not merged without human sign-off.
Commits co-authored by Claude include:

```
Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
```

## What this means for you

- **Code quality:** AI-assisted code is reviewed against the same standards as
  human-written code. CI gates (clippy, biome, ruff, eval suite) enforce quality
  automatically.
- **Security:** Security-critical paths are additionally reviewed by the
  `security-reviewer` subagent using claude-opus-4-7 for deeper reasoning.
- **Reproducibility:** All AI-generated decisions are documented in `decisions/`
  ADRs so future maintainers understand the reasoning.
- **License:** AI-generated code is original work contributed by the founder.
  No GPL, ELv2, or other restrictively-licensed code was used as input.

## Why we're transparent

We believe AI-assisted development is the future of solo-founder infrastructure
companies. We'd rather be honest about it than pretend otherwise. Every line of
production code has been reasoned about and approved by a human.

---

*Last updated: 2026-04-29*
