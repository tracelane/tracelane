## Summary

<!-- One-paragraph summary of what this PR does and why. -->

## Type of change

- [ ] Bug fix (non-breaking, fixes an issue)
- [ ] New feature (non-breaking, adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Performance improvement (hot-path change — benchmark-runner must be green)
- [ ] Security fix (security-reviewer subagent approval required)
- [ ] Documentation only

## Checklist

- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes (no `unwrap()` outside tests)
- [ ] `pnpm lint` passes (Biome)
- [ ] `pnpm typecheck` passes
- [ ] `ruff check .` + `ruff format --check .` pass
- [ ] `pnpm eval:run --suite=all` is green (merge gate)
- [ ] Every new public async fn has `#[tracing::instrument]` with `tenant_id` field
- [ ] New ClickHouse queries include `WHERE tenant_id = ?` (CI grep enforces this)
- [ ] No secrets added (pre-commit + Gitleaks CI enforce this)
- [ ] New dependencies pass `cargo audit` / `pnpm audit`
- [ ] Hot-path changes: `pnpm bench:gateway` / `pnpm bench:ingest` within budget (<10% regression)
- [ ] Security-critical changes (auth, crypto, tenant isolation): security-reviewer subagent approved

## Related issues

Closes #

## Test plan

<!-- Describe how you tested this change. For bug fixes: include the failing eval or test that now passes. -->

## Breaking changes

<!-- If breaking: describe migration path. -->

---

By submitting this pull request, I confirm that my contribution is made under the terms of the Apache 2.0 License and I agree to the Developer Certificate of Origin (DCO):

**DCO 1.1 sign-off:** `Signed-off-by: Full Name <email@example.com>`
