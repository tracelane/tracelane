# @tracelanedev/ui — Neon design system

The Tracelane Neon design system (**ADR-045**, built to the design-system spec):
the token layer, primitives, and the three signature visualizations every dashboard surface
branches from. Phase 0 of the V1 surface rebuild (ADR-046) — the engine is REUSE, the surface is NEW.

## Use

```ts
import "@tracelanedev/ui/styles/tokens.css"; // once, at the app root
import { Button, Card, TranscriptSpine } from "@tracelanedev/ui";
```

## What's here

- **`src/styles/tokens.css`** — Neon tokens, **dark-default + light pairing**, semantic (named by
  role), wired to Tailwind v4 `@theme`. Components read tokens via utilities
  (`bg-surface`, `text-ink`, `text-accent-ink`, `border-seal`) — **never hardcode hex**.
  - `--accent` lime = rationed FUNCTION accent (<10%, never a background). Use `--accent-ink` for any
    legible mark (links/trace-line/data-bars/focus) — it deepens on light; `--accent` is a FILL only,
    always with `--accent-on` on top.
  - `--seal` teal = PROVENANCE signature, **two places only** (differentiator card top-borders + the
    tamper-evident / "Verified · chain ✓" chip + the hash-chain thread).
- **`src/primitives/`** — `Button`, `Card` (`provenance` → teal top-border), `Badge`, `Skeleton`,
  `EmptyState`, `ErrorState`.
- **`src/signature/`** — the purple cow: `TranscriptSpine` (trace detail, replaces the waterfall),
  `HashChainThread` + `ProvenanceChip`, `SeenBeforeSignal`.

## Fonts

Self-host **Space Grotesk** (display/UI) + **JetBrains Mono** (data/code) in the consuming app
(`next/font/google` or `@fontsource`); the tokens reference them by family name.

## Verify

- `pnpm --filter @tracelanedev/ui contrast:check` — WCAG ≥4.5:1 text / ≥3:1 UI proof, **both themes** (CI gate).
- `pnpm --filter @tracelanedev/ui typecheck` · `pnpm --filter @tracelanedev/ui lint`.
- `preview/index.html` — open in a browser: palette / type / signatures, both themes.

## Rules (ADR-045 / the design-system spec)

Dark is the default. Lime is rationed (never lime-flooded). Teal = provenance, 2 places only. No
gradients on dense data surfaces; glass only on transient/data-free surfaces. Tabular numerals on
every figure. Every surface ships its empty / loading / error state. No dead buttons.
