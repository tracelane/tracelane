/**
 * OBS-20 — the end-user identity constant, in a module with NO imports.
 *
 * **Why its own file rather than living in `lib/sessions.ts` beside the type it
 * describes:** `lib/sessions.ts` imports `@/lib/gateway`, which reaches
 * `@workos-inc/authkit-nextjs`, which does not resolve under Vitest's module
 * graph in this Next/pnpm combination. `components/sessions/SessionRow.tsx` was
 * deliberately SPLIT OUT of `app/sessions/page.tsx` (PLT-46) precisely so it
 * would have no server-only imports and its rendered shape could be proven by a
 * real render test — and importing this constant from `lib/sessions.ts` put one
 * straight back, breaking that test suite at collection time.
 *
 * So the rule this file encodes: anything a RENDER-TESTED component needs must
 * live somewhere with no server imports. Found by running the suite, not by
 * reading it.
 */

/**
 * What ingest's PII redaction leaves behind when a customer sends an email
 * address as the end-user id.
 *
 * `crates/ingest/src/clickhouse_writer.rs` runs `tracelane_policy::pii::redact_json`
 * over the whole span-attribute blob before the ClickHouse write, and `email` is
 * one of its categories — so this is the stored value, not a UI placeholder. It
 * must render as an explained state, never blank and never raw: a customer whose
 * privacy control worked correctly should not read it as a broken feature.
 */
export const REDACTED_END_USER = "[REDACTED:email]";

/**
 * ANY redaction placeholder, not just the email one.
 *
 * `crates/policy/src/pii.rs` emits a family — `[REDACTED:email]`,
 * `[REDACTED:phone]`, `[REDACTED:ipv4]`, `[REDACTED:ipv6]`, `[REDACTED:ssn]`,
 * `[REDACTED:credit_card]` and the secret classes — and OBS-20 originally
 * special-cased only the email one.
 *
 * **Why that was a defect and not a cosmetic gap.** A customer using an IP as an
 * end-user id gets `[REDACTED:ipv4]` stored. Matched against the email literal it
 * is merely "truthy and not the placeholder", so it rendered as a REAL LINK to
 * `/traces?end_user=%5BREDACTED%3Aipv4%5D` — and that exact-match filter returns
 * EVERY user whose id was redacted the same way. A collision bucket presented as
 * one person's identity, on the feature whose whole job is "who initiated this".
 *
 * Found by `security-reviewer` on 2026-09-10. The render test could not have
 * caught it: it used `[REDACTED:email]` as its example, which is the single value
 * that passes while the class is broken.
 */
export const REDACTED_PATTERN = /^\[REDACTED:.+\]$/;

/** True for any value PII redaction replaced, whatever the category. */
export function isRedactedEndUser(v: string): boolean {
	return REDACTED_PATTERN.test(v);
}
