/**
 * lanes — multi-agent swimlane grouping (OBS-49), computed client-side from
 * span attributes. No ClickHouse column, no schema change (spec §6) — this is
 * a second PROJECTION of the same spans the tree waterfall already renders.
 *
 * Pure and deterministic — no DOM, no clock, no network (testable in node),
 * matching the discipline `lib/trace-tree.ts` already holds for the tree
 * itself.
 *
 * LANE KEY, per span, in priority order:
 *   1. its OWN `gen_ai.agent.id`    — a SPECIFIC agent instance. This wins
 *      over a name because Claude Code sets `gen_ai_agent_name` as a
 *      session-wide resource attribute shared by every span in the run
 *      (`specs/PLT-46-claude-code-flight-recorder.md:75`) — if name won, a
 *      sub-agent's spans would merge into the root session's lane instead of
 *      getting their own.
 *   2. its OWN `gen_ai_agent_name`  — the canonical stored column (OTLP's
 *      dotted `gen_ai.agent.name` normalises into it at decode time; see
 *      `crates/shared/src/otlp/decode.rs`).
 *   3. INHERITED down the tree from the nearest ancestor that resolved to a
 *      lane — a span with no agent attribute of its own belongs to whichever
 *      agent context it was called from, never to a sibling's.
 *   4. `MAIN_LANE_KEY` ("main") — no agent attribute anywhere on the path to
 *      the root.
 *
 * Lanes are ordered by first-seen span start time (spec §2). A lane's label
 * prefers a known agent NAME; when the lane is keyed by an id and a name is
 * ALSO known for it, the label carries both ("researcher (a1f9c2de)"); an id
 * with no known name shows the short id alone; `MAIN_LANE_KEY` labels "Main".
 *
 * OUT OF SCOPE (spec §6): inferring an agent from a span NAME when no agent
 * attribute exists at all — a span with none is `main`, never guessed.
 */

import type { Span } from "@/components/trace-viewer/types";
import { spanStartUs } from "@/lib/trace-summary";
import {
	type SpanTreeNode,
	buildSpanTree,
	isErrorSpan,
} from "@/lib/trace-tree";

/** The fallback lane for a span with no agent attribute anywhere on its
 * ancestor path — never guessed from a span name (spec §6). */
export const MAIN_LANE_KEY = "main";

export interface Lane {
	key: string;
	label: string;
	spans: Span[];
	/** First-seen start (µs) across the lane's spans — the lane sort key. */
	firstStartUs: number;
	/**
	 * The lane this lane hands off FROM: some span in it carries a
	 * `gen_ai.agent.parent_id` naming another lane's key, and that lane
	 * exists in this trace. Undefined when no hand-off is known (most spans,
	 * and every trace with a single agent) or the named parent never appears
	 * as a lane's own key.
	 */
	handoffFromKey?: string;
}

/** Trace-level rollup for one lane's sticky header (spec §3). */
export interface LaneStats {
	spanCount: number;
	errorCount: number;
	/** Wall-clock span of the lane (max end − min start), microseconds.
	 * Idle gaps are INCLUDED — this is "active window", not busy time. */
	durationUs: number;
}

function parseAttributes(json: string): Record<string, unknown> {
	try {
		const parsed: unknown = JSON.parse(json);
		return parsed && typeof parsed === "object"
			? (parsed as Record<string, unknown>)
			: {};
	} catch {
		return {};
	}
}

function strAttr(
	attrs: Record<string, unknown>,
	key: string,
): string | undefined {
	const v = attrs[key];
	return typeof v === "string" && v !== "" ? v : undefined;
}

interface OwnIdentity {
	/** `gen_ai.agent.id` ?? `gen_ai_agent_name` — undefined when the span
	 * carries neither. */
	key?: string;
	name?: string;
	handoffFromKey?: string;
}

/** This span's OWN agent identity — no inheritance. */
function ownIdentity(span: Span): OwnIdentity {
	const attrs = parseAttributes(span.attributes);
	const id = strAttr(attrs, "gen_ai.agent.id");
	const name = strAttr(attrs, "gen_ai_agent_name");
	return {
		key: id ?? name,
		name,
		handoffFromKey: strAttr(attrs, "gen_ai.agent.parent_id"),
	};
}

const SHORT_ID_LEN = 8;
function shortId(id: string): string {
	return id.length > SHORT_ID_LEN ? id.slice(0, SHORT_ID_LEN) : id;
}

function laneLabel(key: string, name: string | undefined): string {
	if (key === MAIN_LANE_KEY) return "Main";
	if (name === undefined) return shortId(key);
	if (name === key) return name; // resolved via name; no distinct id known
	return `${name} (${shortId(key)})`;
}

/**
 * Group a trace's spans into agent lanes.
 *
 * Walks the span tree from its roots (via {@link buildSpanTree}) with an
 * explicit stack — never native recursion — so a pathologically deep chain
 * cannot blow the call stack, the same discipline `trace-tree.ts` already
 * holds for the tree walk itself. Order of traversal does not affect the
 * result: every span is grouped by key and sorted lanes come from
 * `firstStartUs`, not from visitation order.
 */
export function computeLanes(spans: Span[]): Lane[] {
	const roots = buildSpanTree(spans);
	const byKey = new Map<
		string,
		{
			spans: Span[];
			name?: string;
			firstStartUs: number;
			handoffFromKey?: string;
		}
	>();

	const stack: Array<{ node: SpanTreeNode; inheritedKey: string }> = [];
	for (const root of roots) {
		stack.push({ node: root, inheritedKey: MAIN_LANE_KEY });
	}
	while (stack.length > 0) {
		const frame = stack.pop();
		if (!frame) break;
		const { node, inheritedKey } = frame;
		const own = ownIdentity(node.span);
		const key = own.key ?? inheritedKey;
		const startUs = spanStartUs(node.span);

		let entry = byKey.get(key);
		if (!entry) {
			entry = { spans: [], firstStartUs: startUs };
			byKey.set(key, entry);
		}
		entry.spans.push(node.span);
		if (startUs < entry.firstStartUs) entry.firstStartUs = startUs;
		if (own.name !== undefined) entry.name = own.name;
		if (own.handoffFromKey !== undefined) {
			entry.handoffFromKey = own.handoffFromKey;
		}

		for (const child of node.children) {
			stack.push({ node: child, inheritedKey: key });
		}
	}

	const lanes: Lane[] = [...byKey.entries()].map(([key, e]) => ({
		key,
		label: laneLabel(key, e.name),
		spans: e.spans,
		firstStartUs: e.firstStartUs,
		handoffFromKey:
			e.handoffFromKey !== undefined &&
			e.handoffFromKey !== key &&
			byKey.has(e.handoffFromKey)
				? e.handoffFromKey
				: undefined,
	}));

	lanes.sort((a, b) => a.firstStartUs - b.firstStartUs);
	return lanes;
}

/** Span count, error count and active window for one lane (spec §3). Every
 * number is summed over the lane's own spans — nothing is inferred. */
export function laneStats(lane: Lane): LaneStats {
	let errorCount = 0;
	let minStart = Number.POSITIVE_INFINITY;
	let maxEnd = Number.NEGATIVE_INFINITY;
	for (const s of lane.spans) {
		if (isErrorSpan(s)) errorCount++;
		const start = spanStartUs(s);
		const end = start + Math.max(0, s.duration_us);
		if (start < minStart) minStart = start;
		if (end > maxEnd) maxEnd = end;
	}
	const durationUs = lane.spans.length > 0 ? Math.max(0, maxEnd - minStart) : 0;
	return { spanCount: lane.spans.length, errorCount, durationUs };
}

/** Lanes that contain at least one error span — the unit "Failures only"
 * keeps in Lanes mode (spec §2: "their lane", not per-span ancestors). */
export function lanesWithErrors(lanes: Lane[]): Lane[] {
	return lanes.filter((l) => l.spans.some(isErrorSpan));
}
