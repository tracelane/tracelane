// AUD-40 Part C: answer-first audit summary. Founder 2026-11-19 asked for 50+ scenarios.
// Named cases cover each verdict × coverage × key path; the invariant sweep checks every
// combination of verdict state, chain result, coverage and tail against the spec rules.
import { describe, expect, it } from "vitest";
import { type AuditFacts, summarizeAudit } from "./answer";
import type { AuditVerdict } from "./verdict";

const base: AuditFacts = {
	verdict: { state: "verified", rows: 100, anchors: 1 },
	hashChainValid: true,
	platformVerified: false,
	unanchoredTail: 0,
	checkedRows: 100,
	totalRows: 100,
};
const f = (o: Partial<AuditFacts>): AuditFacts => ({ ...base, ...o });
const s = (o: Partial<AuditFacts>) => summarizeAudit(f(o));

describe("green — only when unchanged, signed+anchored and fully covered", () => {
	it("01 verified, all stored rows checked → ok", () => {
		const r = s({});
		expect(r.tone).toBe("ok");
		expect([r.unaltered.state, r.vouched.state, r.coverage.state]).toEqual([
			"yes",
			"yes",
			"yes",
		]);
		expect(r.headline).toBe("Verified: unchanged, signed and anchored");
	});
	it("02 verified_windowed with full coverage → ok", () => {
		expect(
			s({
				verdict: {
					state: "verified_windowed",
					rows: 50,
					anchors: 1,
					fromSeq: 10,
				},
				checkedRows: 50,
				totalRows: 50,
			}).tone,
		).toBe("ok");
	});
	it("03 platform-signed full coverage → ok, names the platform key", () => {
		const r = s({ platformVerified: true });
		expect(r.tone).toBe("ok");
		expect(r.vouched.text).toMatch(/platform key/);
	});
	it("04 workspace-signed names the workspace key", () => {
		expect(s({}).vouched.text).toMatch(/workspace key/);
	});
	it("05 single row ledger fully checked uses singular wording", () => {
		const r = s({ checkedRows: 1, totalRows: 1 });
		expect(r.coverage.text).toBe("All 1 stored row was checked.");
		expect(r.unaltered.text).toMatch(/\(1 row\)/);
	});
	it("06 next step on green is to save the report", () => {
		expect(s({}).next).toMatch(/Save the check report/);
	});
});

describe("partial coverage — the 1,000-row window on a large ledger", () => {
	it("07 1,000 of 1,000,000 checked → neutral, coverage partly", () => {
		const r = s({ checkedRows: 1000, totalRows: 1_000_000 });
		expect(r.tone).toBe("neutral");
		expect(r.coverage.state).toBe("partly");
		expect(r.coverage.text).toBe(
			"1,000 of 1,000,000 stored rows checked here. The rest need the full export.",
		);
	});
	it("08 partial coverage headline credits what passed", () => {
		expect(s({ checkedRows: 1000, totalRows: 5000 }).headline).toBe(
			"The checked rows passed",
		);
	});
	it("09 partial coverage next step points to the full export and the CLI", () => {
		expect(s({ checkedRows: 10, totalRows: 11 }).next).toMatch(/tlane verify/);
	});
	it("10 total unavailable → coverage unknown, never green", () => {
		const r = s({ totalRows: undefined });
		expect(r.coverage.state).toBe("unknown");
		expect(r.tone).toBe("neutral");
		expect(r.coverage.text).toMatch(/stored total is unavailable/);
	});
	it("11 one billion stored rows formats with separators", () => {
		expect(
			s({ checkedRows: 1000, totalRows: 1_000_000_000 }).coverage.text,
		).toMatch(/1,000,000,000/);
	});
	it("12 checked rows above stored total (late inventory) still reads as all checked", () => {
		expect(s({ checkedRows: 105, totalRows: 100 }).coverage.state).toBe("yes");
	});
	it("13 zero established rows out of a non-empty ledger → unknown, not yes", () => {
		const r = s({ checkedRows: 0, totalRows: 500, hashChainValid: true });
		expect(r.coverage.state).toBe("unknown");
		expect(r.unaltered.state).toBe("unknown");
	});
});

describe("pending public proof", () => {
	it("14 newest rows awaiting anchor → vouched partly", () => {
		const r = s({ unanchoredTail: 12 });
		expect(r.vouched.state).toBe("partly");
		expect(r.vouched.text).toMatch(/newest 12 rows are still waiting/);
	});
	it("15 pending tail headline", () => {
		expect(s({ unanchoredTail: 3 }).headline).toBe(
			"Unchanged. Public proof is partly pending",
		);
	});
	it("16 pending tail next step is to reload later", () => {
		expect(s({ unanchoredTail: 3 }).next).toMatch(/Reload in a few minutes/);
	});
	it("17 a single pending row uses singular wording", () => {
		expect(s({ unanchoredTail: 1 }).vouched.text).toMatch(
			/newest 1 row is still waiting/,
		);
	});
	it("18 pending tail is never green", () => {
		expect(s({ unanchoredTail: 1 }).tone).not.toBe("ok");
	});
});

describe("qualified states — never green, never an accusation", () => {
	it("19 chain_only → vouched partly, neutral", () => {
		const r = s({ verdict: { state: "chain_only", rows: 100 } });
		expect(r.tone).toBe("neutral");
		expect(r.vouched.state).toBe("partly");
		expect(r.unaltered.state).toBe("yes");
	});
	it("20 anchor_hole names the uncovered rows", () => {
		const r = s({ verdict: { state: "anchor_hole", rows: 7 } });
		expect(r.vouched.text).toBe("7 rows sit outside every signed batch.");
		expect(r.tone).toBe("neutral");
	});
	it("21 anchor_hole of one row uses singular wording", () => {
		expect(s({ verdict: { state: "anchor_hole", rows: 1 } }).vouched.text).toBe(
			"1 row sits outside every signed batch.",
		);
	});
	it("22 anchors_unverifiable → vouched unknown, specific headline", () => {
		const r = s({ verdict: { state: "anchors_unverifiable", anchors: 2 } });
		expect(r.vouched.state).toBe("unknown");
		expect(r.headline).toBe("Signatures could not be checked");
		expect(r.next).toMatch(/trusted audit key/);
	});
	it("23 unrooted_window → unaltered unknown even if hashes link", () => {
		const r = s({
			verdict: { state: "unrooted_window" },
			hashChainValid: true,
		});
		expect(r.unaltered.state).toBe("unknown");
		expect(r.vouched.state).toBe("unknown");
		expect(r.tone).toBe("neutral");
	});
	it("24 unrooted_window headline does not accuse", () => {
		expect(s({ verdict: { state: "unrooted_window" } }).headline).toBe(
			"Integrity not established by this check",
		);
	});
});

describe("real failures — red", () => {
	it("25 chain_broken → danger, unaltered no", () => {
		const r = s({
			verdict: { state: "chain_broken", rows: 100, firstSeq: 42 },
			hashChainValid: false,
		});
		expect(r.tone).toBe("danger");
		expect(r.unaltered.state).toBe("no");
		expect(r.headline).toBe("Integrity check failed");
	});
	it("26 chain_broken does not assess signatures past the break", () => {
		expect(
			s({
				verdict: { state: "chain_broken", rows: 1, firstSeq: null },
				hashChainValid: false,
			}).vouched.state,
		).toBe("unknown");
	});
	it("27 stripped → danger, vouched no", () => {
		const r = s({ verdict: { state: "stripped" } });
		expect(r.tone).toBe("danger");
		expect(r.vouched.state).toBe("no");
		expect(r.headline).toBe("A public proof is missing");
	});
	it("28 signature_failed → danger, vouched no", () => {
		const r = s({
			verdict: { state: "signature_failed", reasons: ["bad_attestation_sig"] },
		});
		expect(r.tone).toBe("danger");
		expect(r.vouched.state).toBe("no");
	});
	it("29 every red state tells the user to send the report to support", () => {
		for (const verdict of [
			{ state: "chain_broken", rows: 1, firstSeq: 1 },
			{ state: "stripped" },
			{ state: "signature_failed", reasons: [] },
		] as AuditVerdict[])
			expect(
				s({
					verdict,
					hashChainValid: verdict.state !== "chain_broken",
				}).next,
			).toMatch(/send it to support/);
	});
	it("30 a failure stays red even with full coverage and a platform key", () => {
		expect(
			s({ verdict: { state: "stripped" }, platformVerified: true }).tone,
		).toBe("danger");
	});
	it("31 a failure keeps the coverage answer so the scope is still visible", () => {
		expect(
			s({ verdict: { state: "stripped" }, checkedRows: 10, totalRows: 20 })
				.coverage.state,
		).toBe("partly");
	});
});

describe("no report / empty / read errors", () => {
	it("32 ready → neutral, all unknown, 'Checking'", () => {
		const r = s({ verdict: { state: "ready" }, hashChainValid: null });
		expect([r.unaltered.state, r.vouched.state, r.coverage.state]).toEqual([
			"unknown",
			"unknown",
			"unknown",
		]);
		expect(r.headline).toBe("Checking your evidence");
	});
	it("33 ready ignores a stale hashChainValid", () => {
		expect(
			s({ verdict: { state: "ready" }, hashChainValid: true }).unaltered.state,
		).toBe("unknown");
	});
	it("34 empty ledger → 'No evidence yet', start recording", () => {
		const r = s({
			verdict: { state: "empty" },
			hashChainValid: null,
			checkedRows: 0,
			totalRows: 0,
		});
		expect(r.headline).toBe("No evidence yet");
		expect(r.next).toMatch(/Route a call/);
	});
	it("35 empty window over a non-empty ledger says rows are outside the window", () => {
		expect(
			s({
				verdict: { state: "empty" },
				hashChainValid: null,
				checkedRows: 0,
				totalRows: 40,
			}).coverage.text,
		).toBe("40 stored rows are outside this window.");
	});
	it("36 401 → sign in again", () => {
		const r = s({ readError: "unauthorized" });
		expect(r.next).toBe("Sign in again, then reload this page.");
		expect(r.tone).toBe("neutral");
	});
	it("37 403 → ask an admin", () => {
		expect(s({ readError: "forbidden" }).next).toMatch(/workspace admin/);
	});
	it("38 other read failure → retry, then support", () => {
		expect(s({ readError: "failed" }).next).toMatch(/Reload to retry/);
	});
	it("39 a read error overrides any verdict, even a passing one", () => {
		const r = s({ readError: "failed" });
		expect(r.unaltered.state).toBe("unknown");
		expect(r.tone).not.toBe("ok");
	});
	it("40 read error headline", () => {
		expect(s({ readError: "forbidden" }).headline).toBe(
			"We couldn’t check your evidence",
		);
	});
});

describe("unaltered is derived only from the hash chain", () => {
	it("41 hashChainValid null with a verified verdict → unknown, so never green", () => {
		const r = s({ hashChainValid: null });
		expect(r.unaltered.state).toBe("unknown");
		expect(r.tone).toBe("neutral");
	});
	it("42 hashChainValid false with a non-broken verdict → unaltered no", () => {
		expect(
			s({
				verdict: { state: "signature_failed", reasons: [] },
				hashChainValid: false,
			}).unaltered.state,
		).toBe("no");
	});
	it("43 zero checked rows never claims unchanged", () => {
		expect(s({ checkedRows: 0 }).unaltered.state).toBe("unknown");
	});
});

// ---- Invariant sweep across every combination (spec §5 rules) ----
const verdicts: AuditVerdict[] = [
	{ state: "ready" },
	{ state: "verified", rows: 5, anchors: 1 },
	{ state: "verified_windowed", rows: 5, anchors: 1, fromSeq: 2 },
	{ state: "chain_only", rows: 5 },
	{ state: "empty" },
	{ state: "chain_broken", rows: 5, firstSeq: 3 },
	{ state: "unrooted_window" },
	{ state: "anchors_unverifiable", anchors: 1 },
	{ state: "anchor_hole", rows: 2 },
	{ state: "stripped" },
	{ state: "signature_failed", reasons: ["x"] },
];
const coverages: Array<[number, number | undefined]> = [
	[5, 5],
	[5, 50],
	[5, undefined],
	[0, 0],
];
const combos = verdicts.flatMap((verdict) =>
	[true, false, null].flatMap((hashChainValid) =>
		coverages.flatMap(([checkedRows, totalRows]) =>
			[0, 4].flatMap((unanchoredTail) =>
				[false, true].map((platformVerified) => ({
					verdict,
					hashChainValid,
					checkedRows,
					totalRows,
					unanchoredTail,
					platformVerified,
				})),
			),
		),
	),
);

describe(`invariants over ${combos.length} combinations`, () => {
	const RED = new Set(["chain_broken", "stripped", "signature_failed"]);
	it("44 green ⇒ yes, yes, yes", () => {
		for (const c of combos) {
			const r = summarizeAudit(c);
			if (r.tone === "ok")
				expect([r.unaltered.state, r.vouched.state, r.coverage.state]).toEqual([
					"yes",
					"yes",
					"yes",
				]);
		}
	});
	it("45 red ⇔ a real failure verdict", () => {
		for (const c of combos)
			expect(summarizeAudit(c).tone === "danger").toBe(
				RED.has(c.verdict.state),
			);
	});
	it("46 no 'yes' without a report (ready/empty)", () => {
		for (const c of combos.filter(
			(c) => c.verdict.state === "ready" || c.verdict.state === "empty",
		)) {
			const r = summarizeAudit(c);
			expect([
				r.unaltered.state,
				r.vouched.state,
				r.coverage.state,
			]).not.toContain("yes");
		}
	});
	it("47 unaltered 'yes' only when the hash chain passed on checked rows", () => {
		for (const c of combos)
			if (summarizeAudit(c).unaltered.state === "yes")
				expect(c.hashChainValid === true && c.checkedRows > 0).toBe(true);
	});
	it("48 coverage 'yes' only when every stored row was checked", () => {
		for (const c of combos)
			if (summarizeAudit(c).coverage.state === "yes")
				expect(
					c.totalRows !== undefined &&
						c.checkedRows >= c.totalRows &&
						c.totalRows > 0,
				).toBe(true);
	});
	it("49 a pending tail is never green", () => {
		for (const c of combos.filter((c) => c.unanchoredTail > 0))
			expect(summarizeAudit(c).tone).not.toBe("ok");
	});
	it("50 never claims recording was complete (ADR-077)", () => {
		for (const c of combos) {
			const r = summarizeAudit(c);
			const all = [
				r.headline,
				r.unaltered.text,
				r.vouched.text,
				r.coverage.text,
				r.next,
			].join(" ");
			expect(all).not.toMatch(
				/every call|all calls|complete record|nothing was missed/i,
			);
		}
	});
	it("51 no internal or spec ids in any visible text", () => {
		for (const c of combos) {
			const r = summarizeAudit(c);
			const all = [
				r.headline,
				r.unaltered.text,
				r.vouched.text,
				r.coverage.text,
				r.next,
			].join(" ");
			expect(all).not.toMatch(/\b(AUD|ADR|RI|ACT|OBS|B)-\d+/);
		}
	});
	it("52 every text is non-empty and ends with punctuation or an ellipsis", () => {
		for (const c of combos) {
			const r = summarizeAudit(c);
			for (const t of [
				r.unaltered.text,
				r.vouched.text,
				r.coverage.text,
				r.next,
			])
				expect(t).toMatch(/[.…]$/);
			expect(r.headline.length).toBeGreaterThan(0);
		}
	});
	it("53 deterministic: the same facts give the same summary", () => {
		for (const c of combos)
			expect(summarizeAudit(c)).toEqual(summarizeAudit({ ...c }));
	});
	it("54 the platform flag never turns a failure or a partial into green", () => {
		for (const c of combos.filter((c) => c.platformVerified)) {
			const r = summarizeAudit(c);
			if (r.tone === "ok")
				expect(
					c.verdict.state === "verified" ||
						c.verdict.state === "verified_windowed",
				).toBe(true);
		}
	});
	it("55 a read error always yields three unknowns", () => {
		for (const c of combos) {
			const r = summarizeAudit({ ...c, readError: "failed" });
			expect([r.unaltered.state, r.vouched.state, r.coverage.state]).toEqual([
				"unknown",
				"unknown",
				"unknown",
			]);
		}
	});
	it("56 red verdicts always name a concrete next step to support", () => {
		for (const c of combos.filter((c) => RED.has(c.verdict.state)))
			expect(summarizeAudit(c).next).toMatch(/support/);
	});
	it("57 neutral never uses the green headline", () => {
		for (const c of combos) {
			const r = summarizeAudit(c);
			if (r.tone !== "ok")
				expect(r.headline).not.toBe("Verified: unchanged, signed and anchored");
		}
	});
	it("58 coverage text always states numbers it was given", () => {
		for (const c of combos.filter(
			(c) =>
				c.totalRows &&
				c.checkedRows > 0 &&
				!["ready", "empty"].includes(c.verdict.state),
		))
			expect(summarizeAudit(c).coverage.text).toContain(String(c.totalRows));
	});
	it("59 an unknown total never produces a partial or complete coverage claim", () => {
		for (const c of combos.filter((c) => c.totalRows === undefined))
			expect(summarizeAudit(c).coverage.state).toBe("unknown");
	});
	it("60 the sweep exercises every verdict state", () => {
		expect(new Set(combos.map((c) => c.verdict.state)).size).toBe(11);
	});
});

describe("wiring as the page passes it (#385 review)", () => {
	it("61 chain_only with the loaded rows as checked rows → unchanged yes, vouched partly", () => {
		const r = summarizeAudit({
			verdict: { state: "chain_only", rows: 40 },
			hashChainValid: true,
			platformVerified: false,
			unanchoredTail: 0,
			checkedRows: 40,
			totalRows: 40,
		});
		expect([r.unaltered.state, r.vouched.state, r.coverage.state]).toEqual([
			"yes",
			"partly",
			"yes",
		]);
		expect(r.tone).toBe("neutral");
	});
	it("62 an untrusted window passes zero checked rows → nothing claimed", () => {
		const r = summarizeAudit({
			verdict: { state: "anchors_unverifiable", anchors: 1 },
			hashChainValid: true,
			platformVerified: false,
			unanchoredTail: 0,
			checkedRows: 0,
			totalRows: 40,
		});
		expect(r.unaltered.state).toBe("unknown");
		expect(r.coverage.state).toBe("unknown");
	});
});
