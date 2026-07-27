# apps/docs/

Mintlify-based public documentation site for Tracelane.

## Structure

- `docs.json` — Mintlify configuration (theme, navigation, branding)
- `index.mdx` — landing page
- `quickstart.mdx`, `onboarding.mdx`, `architecture.mdx`, `predictive-guardrails.mdx`, `providers.mdx`, `cli.mdx`, `api-reference.mdx` — top-level docs
- `decisions/` — ADR rollup
- `migrations/` — from-helicone / from-litellm / from-langfuse

## Local preview

```bash
npm install -g mintlify
cd apps/docs
mintlify dev
```

The site is served at `http://localhost:3000`.

## Source-of-truth note

These MDX pages are the **public-facing copy**. The deeper engineering
prose lives in `/docs/*.md` at the repo root. Both should stay in sync;
the public copy is shorter and Mintlify-flavoured (Cards, Steps,
CodeGroups), while the repo-root copy is plain GitHub-rendered Markdown
optimised for code review.

When updating either:

1. If the change is purely cosmetic / Mintlify-component-only, update
   `apps/docs/` only.
2. If the change is a fact (new env var, new endpoint, new provider),
   update both.
3. CI does **not** currently diff the two. Treat that as a known TODO.

## Deploy

The site is deployed via Mintlify's GitHub integration. Pushing to
`main` triggers a rebuild; previews are auto-generated on PR.
