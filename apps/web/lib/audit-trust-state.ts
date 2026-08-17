/**
 * ┌─ ACCEPTED 2026-08-15 — EARNED TODAY, AND ON NOTICE. Founder ruling. ────────────┐
 *
 * This file is the exact shape `docs/reference/TRAPS.md` §34 warns about: logic
 * extracted out of a component into a pure function, with its own passing unit tests.
 * §34 was earned HERE — a `verifier` reinstated both of R43's original bugs directly in
 * `AuditLedgerView.tsx` and **all 523 tests passed**. Pure tests on this file prove this
 * file. They prove nothing about the component that calls it, and the customer-visible
 * defect lives in the component.
 *
 * The extraction was accepted anyway, for one reason and not the obvious one: it makes
 * "borrowing another state's copy" a *type* error (the discriminated union below), and
 * the render-path proof was then actually done — `components/audit/audit-ledger-verify.test.ts`
 * renders the real component with `renderToStaticMarkup` over real production shapes, and
 * reinstating both bugs turns **three** tests red. It was accepted because that assertion
 * exists, NOT because this file is well tested.
 *
 * THE CONDITION A FUTURE READER INHERITS. The acceptance is contingent, and it lapses
 * silently if any of these stops being true:
 *
 *   1. A mutation to the RENDER PATH — `AuditLedgerView.tsx`, not this file — turns a
 *      test red. That is the only form of §22 that is a control. Adding cases here
 *      without adding the matching rendered assertion re-creates the exact §34 defect.
 *   2. Every state in the union below is asserted through the rendered markup, not just
 *      through `auditTrustState()`'s return value.
 *   3. The current design-system decision record binds this file through the UI
 *      renovation: the four-state machine is **correctness, not styling**. Its logic
 *      and its copy survive the redesign unchanged. Restyling the card is in scope;
 *      changing which state renders which sentence is not, and needs its own ruling.
 *      (This file is in the PUBLIC export set, so the governing ADR is referenced by
 *      role rather than by number — see `decisions/` in the private repo.)
 *
 * If you are here to add a fifth state, or because a redesign made the copy inconvenient:
 * read §34 first, then write the rendered assertion BEFORE the change, and prove it fails.
 * "I added tests" is not the claim — the claim is "I broke it and they caught it".
 *
 * └────────────────────────────────────────────────────────────────────────────────┘
 */

/**
 * R43 — the audit ledger's trust state, as ONE pure decision.
 *
 * WHY THIS IS A FUNCTION AND NOT AN INLINE TERNARY. It used to be
 * `!tenantPubkeyB64 || anchorRecords.length === 0`, a single branch collapsing two
 * unrelated facts: "you have no data yet" and "we cannot give you a trust root you can
 * check us with". R21 then gave five production tenants a real `audit_anchor_records`
 * row, so the second half of that OR became false while the first half kept
 * short-circuiting on a 404'd pubkey — and the card kept rendering **"No signed batches
 * yet"** over 57 signed rows and a real anchor record. A false sentence, shown to a
 * customer, about the one property the product is sold on.
 *
 * Collapsed states are the defect class (B-241, B-249). A discriminated union makes
 * "borrowing another state's copy" a type error rather than a judgement call, and lets
 * every state be asserted without a DOM.
 */

export type AuditTrustState =
	/** No anchor records at all — genuinely nothing has been signed yet. */
	| "no-batches"
	/**
	 * Signed, but with Tracelane's OPERATOR key: this workspace has no per-tenant key,
	 * so `/v1/audit/pubkey` cannot hand a third party an out-of-band trust root. Real
	 * tamper-evidence, NOT independently verifiable. Must never borrow "no-batches"
	 * copy (it has data) or "tenant-signed" copy (it is not their key).
	 */
	| "operator-signed"
	/** Signed with the workspace's OWN key, but not yet in a public transparency log. */
	| "tenant-signed"
	/** At least one batch is in Sigstore Rekor with a resolved log index. */
	| "publicly-anchored";

export interface AuditTrustInput {
	/** Rows in `audit_anchor_records` for this tenant — anchored OR not. */
	anchorRecordCount: number;
	/**
	 * Records that are genuinely in the public log (`anchor_state === "anchored"` AND a
	 * `rekor.log_index`). A record is written for every SIGNED batch, so this is NOT the
	 * same as `anchorRecordCount` — conflating them claims public anchoring for batches
	 * that reached no log.
	 */
	anchoredCount: number;
	/**
	 * The tenant's Ed25519 public key from `GET /v1/audit/pubkey`.
	 *
	 * Absent covers TWO production shapes and both must resolve the same way: a **404**
	 * (no `tenant_audit_keys` row), and a **200 carrying an empty string** — a legacy row
	 * minted before the key's public half was persisted, which is success-shaped and
	 * carries nothing. An empty key is not a trust root, so it is treated as absent.
	 */
	tenantPubkeyB64?: string | null;
}

/** True only for a pubkey a third party could actually verify against. */
export function hasUsableTrustRoot(tenantPubkeyB64?: string | null): boolean {
	return (
		typeof tenantPubkeyB64 === "string" && tenantPubkeyB64.trim().length > 0
	);
}

/** Structural shape of a parsed `type:"anchor"` line — only the fields this decides on. */
export interface AnchorRecordLike {
	anchor_state?: string;
	rekor?: { log_index?: string };
}

/**
 * R48 — THE single definition of "this record claims public anchoring".
 *
 * `AuditLedgerView.tsx` had THREE predicates for the phrase "publicly anchored", and two
 * of them provably disagreed on exactly the tenant class this work is about: for a ledger
 * with one real Rekor anchor and no fetchable tenant pubkey, `anchoredIndices.length` was
 * **1** while `report.anchors_included` was **0** — because the verifier cannot CHECK an
 * anchor without a trusted key and counts it `anchors_unverified` instead
 * (`packages/verifier-typescript/src/index.ts:810-813`). One panel showed "Publicly
 * anchored" and "Anchor verification failed" at the same time.
 *
 * **This counts what the LEDGER CLAIMS.** It is deliberately NOT the same question as
 * `report.anchors_included`, which counts what the verifier CONFIRMED — a strictly
 * stronger fact. Both are legitimate; conflating them is the bug. So the UI keeps two
 * distinct words: this predicate may say *"publicly anchored"*, and only
 * `anchors_included` may say *"independently verified"*. If you find yourself wanting a
 * third, that is this defect returning.
 */
export function anchoredRecords<T extends AnchorRecordLike>(
	records: readonly T[],
): T[] {
	return records.filter(
		(a) => a.anchor_state === "anchored" && Boolean(a.rekor?.log_index),
	);
}

/** Count of the above. Everything that says "publicly anchored" derives from these two. */
export function anchoredRecordCount(
	records: readonly AnchorRecordLike[],
): number {
	return anchoredRecords(records).length;
}

export function auditTrustState(input: AuditTrustInput): AuditTrustState {
	const { anchorRecordCount, anchoredCount, tenantPubkeyB64 } = input;

	// Order is load-bearing. "No data" is decided FIRST and on its own predicate, so no
	// later condition can ever be mistaken for emptiness — that mistake is the bug.
	if (anchorRecordCount <= 0) return "no-batches";
	if (anchoredCount > 0) return "publicly-anchored";
	return hasUsableTrustRoot(tenantPubkeyB64)
		? "tenant-signed"
		: "operator-signed";
}
