# `crates/policy`

Cedar policy evaluation for the Tracelane gateway.

[Cedar](https://www.cedarpolicy.com/) is AWS's open-source policy language.
Tracelane uses it to express **per-tenant access-control policies** for gateway
routing, data export, retention overrides, and predictive-layer configuration.

- Policies are stored in Postgres and evaluated **inline on each request**.
- The `cedar-policy` crate is the authoritative evaluator.
- This is distinct from **entitlements** (feature gating, in
  `workspace_entitlements`) and from operational **kill-switches** — policy
  answers "is this principal allowed this action on this resource", entitlements
  answer "does this plan include this feature".

~14 public items. See `../../docs/REPO_MAP.md`.
