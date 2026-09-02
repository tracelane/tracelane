import {
	ScoresTable,
	SummaryStrip,
} from "@/components/settings/OnlineEvalsManager";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

/**
 * `EVL-28` item 11 — the rendered-shape proof for online evals.
 *
 * WHY THESE EXIST, and it is one property rather than a suite:
 *
 * **ZERO AND UNKNOWN MUST NOT RENDER THE SAME.** The gateway goes to real
 * trouble to keep them apart — `achieved_sample_rate` is `null` when nothing
 * was eligible rather than `0.0`, `mean_score` is `null` when nothing scored,
 * `score` is `NULL` on a judge whose response failed validation, `cost_usd` is
 * `NULL` for an unpriced model — and every one of those distinctions dies at
 * the last hop if a component renders `null` as a number. A quiet day and a
 * broken sampler would then look identical on the one page a customer opens to
 * ask which it is.
 *
 * A screenshot cannot prove this, because the failure mode is a plausible
 * number in the right place. Only asserting BOTH directions can: the null case
 * must say words, and the measured-zero case must say a number. A test that
 * only checked the null case would pass on a component that rendered "no
 * traffic in this window" unconditionally.
 *
 * OBSERVED BLOCKING, not assumed: changing `achieved_sample_rate === null` to
 * `!s.achieved_sample_rate` in the component — the obvious "simplification",
 * and the one that reintroduces the bug — fails test 2, because a measured 0
 * is falsy and would then render as "no traffic in this window".
 */

/**
 * Slice the markup for ONE stat tile, by its label.
 *
 * **The whole-document `not.toContain` is a trap, and it caught this file on its
 * first run.** Asserting the summary "does not contain 0.0%" failed on the
 * CONFIGURED tile's own sub-line ("10.0% of eligible requests") while the
 * ACHIEVED tile was rendering exactly right; asserting the score table "does not
 * contain 0.00" failed on a neighbouring row's `$0.0001`. Both times the
 * component was correct and the assertion was measuring the wrong region — a
 * probe that cannot tell the two answers apart. A negative assertion has to be
 * scoped to the element that would carry the defect, or it reports on whatever
 * else happens to share a substring.
 */
function tile(html: string, label: string): string {
	const at = html.indexOf(label);
	if (at < 0) throw new Error(`no tile labelled ${label}`);
	const next = html.indexOf("stat-tile", at);
	return html.slice(at, next < 0 ? html.length : next);
}

/**
 * The visible text of one score row's cells, in column order:
 * `[trace, rubric, score, verdict, cost, scored_at]`.
 *
 * CELLS, not a substring of the row — because the row's own trace id is a run
 * of digits and a `not.toMatch(/>\d/)` over the raw markup matches it, which is
 * the second time in this file a negative assertion measured the wrong region.
 * The claim is about the SCORE COLUMN, so the assertion has to be about the
 * score column.
 */
function cells(html: string, traceId: string): string[] {
	const at = html.indexOf(traceId);
	if (at < 0) throw new Error(`no row for ${traceId}`);
	const start = html.lastIndexOf("<tr", at);
	const end = html.indexOf("</tr>", at);
	const slice = html.slice(start, end < 0 ? html.length : end);
	return [...slice.matchAll(/<td\b[^>]*>([\s\S]*?)<\/td>/g)].map((m) =>
		// Strip nested markup (the trace link, the verdict badge) down to text.
		(m[1] ?? "")
			.replace(/<[^>]*>/g, "")
			.trim(),
	);
}

const BASE = {
	window_hours: 24,
	configured_sample_rate: 0.1,
	enabled: true,
	achieved_sample_rate: null as number | null,
	eligible_spans: 0,
	sampled_traces: 0,
	scored: 0,
	errored: 0,
	mean_score: null as number | null,
	judge_cost_usd: null as number | null,
	judge_budget_usd_monthly: 5,
};

describe("online evals — zero is not unknown", () => {
	it("renders words, not 0%, when nothing was eligible", () => {
		const achieved = tile(
			renderToStaticMarkup(h(SummaryStrip, { s: BASE })),
			"Sampling — achieved",
		);
		expect(achieved).toContain("no traffic in this window");
		// The bug this whole distinction exists to prevent — scoped to the tile
		// that would carry it, never to the whole document.
		expect(achieved).not.toContain("0.00%");
		expect(achieved).not.toContain("0.0%");
	});

	it("renders a NUMBER, not words, when the achieved rate is a measured zero", () => {
		// 269 eligible traces and none sampled is a real, measured 0% — a
		// sampler that is running and has not drawn yet. It must NOT read as
		// "no traffic": that is the opposite diagnosis.
		const achieved = tile(
			renderToStaticMarkup(
				h(SummaryStrip, {
					s: { ...BASE, achieved_sample_rate: 0, eligible_spans: 269 },
				}),
			),
			"Sampling — achieved",
		);
		expect(achieved).not.toContain("no traffic in this window");
		expect(achieved).toContain("0.00%");
		expect(achieved).toContain("269");
	});

	it("shows configured AND achieved as two separately labelled numbers", () => {
		const html = renderToStaticMarkup(
			h(SummaryStrip, {
				s: {
					...BASE,
					achieved_sample_rate: 0.072,
					eligible_spans: 500,
					sampled_traces: 36,
				},
			}),
		);
		// Both labels, always. Presenting achieved as the setting fabricates an
		// observation; presenting configured alone hides a real one.
		expect(html).toContain("Sampling — configured");
		expect(html).toContain("Sampling — achieved");
		expect(html).toContain("1 in 10"); // configured 0.10
		expect(html).toContain("7.2%"); // achieved, counted
	});

	it("renders a disabled policy as 'off', never as a 0% rate", () => {
		const html = renderToStaticMarkup(
			h(SummaryStrip, { s: { ...BASE, enabled: false } }),
		);
		expect(html).toContain("off");
		expect(html).toContain("no policy is sampling");
	});

	it("renders an em-dash for an unmeasurable mean, and a number for a real one", () => {
		const none = tile(
			renderToStaticMarkup(h(SummaryStrip, { s: BASE })),
			"Mean score",
		);
		expect(none).toContain("nothing scored yet");
		expect(none).not.toContain("0.00");
		const some = tile(
			renderToStaticMarkup(
				h(SummaryStrip, { s: { ...BASE, mean_score: 0.87, scored: 4 } }),
			),
			"Mean score",
		);
		expect(some).toContain("0.87");
		expect(some).not.toContain("nothing scored yet");
	});
});

describe("online evals — an errored judge has no score, not a zero", () => {
	const scored = {
		trace_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		span_id: "s1",
		rubric: "answers_the_question",
		judge_model: "vertex/gemini-2.5-flash-lite",
		status: "scored",
		score: 0.87,
		verdict: "pass",
		reason: "answers it",
		error: null as string | null,
		cost_usd: 0.000123,
		latency_ms: 412,
		scored_at: 1_756_000_000_000,
	};
	const errored = {
		...scored,
		trace_id: "11111111-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		span_id: "s2",
		status: "errored",
		score: null,
		verdict: "",
		reason: "",
		error: "judge_schema_invalid",
		cost_usd: null,
	};

	it("renders the score for a scored row and an em-dash for an errored one", () => {
		const html = renderToStaticMarkup(
			h(ScoresTable, { scores: [scored, errored] }),
		);
		const [, , goodScore, goodVerdict, goodCost] = cells(html, scored.trace_id);
		expect(goodScore).toBe("0.87");
		expect(goodVerdict).toBe("pass");
		expect(goodCost).toBe("$0.0001");

		const [, , badScore, badVerdict, badCost] = cells(html, errored.trace_id);
		expect(badVerdict).toBe("not judged");
		// A NUMBER in either cell would be fabricated: a grade from a judge that
		// never produced one, or a price for a call we could not price. Both are
		// the §21 failure this feature sits downstream of, and both must read as
		// "we do not know" rather than as zero.
		expect(badScore).toBe("—");
		expect(badCost).toBe("—");
		expect(badScore).not.toMatch(/\d/);
	});

	it("says so when the window is empty, rather than rendering an empty table", () => {
		const html = renderToStaticMarkup(h(ScoresTable, { scores: [] }));
		expect(html).toContain("Nothing scored in this window");
	});
});
