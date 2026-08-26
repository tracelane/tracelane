<!-- tracelane:classification: PUBLIC -->
# @tracelanedev/ui — the Tracelane design system

The token layer, primitives and signature visualizations every dashboard surface branches
from.

> **One source, and this file is not it.** `src/styles/tokens.css` is the **only** definition
> of colour, type and layout. If this README and that file ever disagree, **the file wins and
> this README is the defect** — which is exactly what happened here: until 2026-08-15 this
> page described a "Neon" system (lime, teal, Space Grotesk, dark-default) that had been
> superseded **twice** and matched nothing in the package it documents. It is deliberately
> short now, so it cannot rot that way again.

## Use

<!-- This package is `private: true` and is NOT published to npm. It is a
     workspace-internal design system consumed by `apps/web` through the pnpm
     workspace. `npm install @tracelanedev/ui` will not resolve. -->

**This package is not published to npm.** It is an internal workspace package
consumed by `apps/web` through the pnpm workspace; it is included here so the
dashboard's component source is readable, not as an installable dependency.

From inside this repository:

```ts
import "@tracelanedev/ui/styles/tokens.css"; // once, at the app root
import { Button, Card, TranscriptSpine } from "@tracelanedev/ui";
```

## What's here

- **`src/styles/tokens.css`** — the tokens, both themes, semantic (**named by role, never by
  colour**) and wired to Tailwind v4 `@theme`. Components read them through utilities
  (`bg-surface`, `text-ink`, `border-…`) and **never hardcode hex**. That discipline is
  measured, not aspirational: there are **zero** numbered Tailwind palette utilities
  (`bg-slate-900`-style) anywhere in the app.
- **`src/primitives/`** — `Button`, `Card`, `Badge`, `Skeleton`, `EmptyState`, `ErrorState`.
- **`src/signature/`** — `TranscriptSpine` (trace detail), `HashChainThread`,
  `ProvenanceChip`, `SeenBeforeSignal`.

## Fonts

Wired by the consuming app and exposed to the tokens as `--font-sans` / `--font-mono` /
`--font-display`. The app currently self-hosts its UI face via `next/font`; **the tokens
reference families by name only and do not load anything.**

## Verify

- `pnpm --filter @tracelanedev/ui contrast:check` — WCAG ≥4.5:1 text / ≥3:1 UI, both themes.
  **Now genuinely a gate**: `scripts/verify-all.sh` runs it, and `--selftest` proves it goes
  red on a low-contrast pair. Until 2026-08-15 this README called it "(CI gate)" while it was
  invoked by nothing *and* carried two bugs that hid each other — it labelled the light block
  "DARK" and then threw on a dark selector that had never existed. A doc asserting a control
  that does not exist is worse than no doc; this line is now checked by the thing it describes.
- `pnpm --filter @tracelanedev/ui typecheck` · `pnpm --filter @tracelanedev/ui lint`.

## Removed

`preview/index.html` was **deleted 2026-08-15**, not merely un-linked. It rendered a
palette page for the retired "Neon" system — two generations stale — and shipped publicly.
It rotted because `package.json`'s `preview` script pointed at
`scripts/build-preview.mjs`, **a generator that does not exist**, so the page could never
be regenerated and nothing ever failed to say so. The dead script is gone too. If a preview
page comes back, it must be **generated from `tokens.css`**, like `contrast-check.mjs` is —
a hand-maintained copy of the palette is a second source of truth by construction.

## Rules

Semantic tokens only — a palette swap must never touch component code. Tabular numerals on
every figure. Every surface ships its empty / loading / error state. No dead buttons.

**Colour is data.** Chrome is monochrome; a colour on screen means something happened.
The full decision record is private to the Tracelane repo.
