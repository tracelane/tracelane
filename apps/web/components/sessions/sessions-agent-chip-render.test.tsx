/**
 * PLT-46 — the agent-name chip on `/sessions`, proven against real markup.
 *
 * The gateway is gaining `agent_name` on `GET /v1/sessions` rows separately
 * (Rust, `trace_reads.rs`'s session SELECT) — `SessionSummary.agent_name` is
 * typed OPTIONAL (`apps/web/lib/sessions.ts`) precisely so this page works
 * before and after that deploys. Two directions matter, same as
 * `shell-nav-render.test.ts`'s header comment on why this renders instead of
 * reading a config object: a chip that always shows (or never shows) would
 * look identical to a correct build until read against real markup.
 *
 *   1. `agent_name: "claude-code"` renders a chip carrying that text.
 *   2. `agent_name` absent, and `agent_name: ""`, both render NO chip — the
 *      two ways today's data can say "no agent" (field not yet deployed by
 *      the gateway; field deployed but empty on this session).
 *
 * Imports `SessionRow` from this directory's `SessionRow.tsx`, not from
 * `app/sessions/page.tsx` — that module's header comment explains why: the
 * page's data-fetching imports drag in `@workos-inc/authkit-nextjs`, whose
 * `next/cache` subpath import does not resolve under Vitest's module graph.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// next/link renders a plain anchor in this environment — same stub as
// shell-nav-render.test.ts, needed because SessionRow links to the session
// detail page.
vi.mock("next/link", () => ({
	default: ({ href, children, ...rest }: Record<string, unknown>) =>
		createElement("a", { href, ...rest }, children as never),
}));

import type { SessionSummary } from "@/lib/sessions";
import { SessionRow } from "./SessionRow";

const BASE: SessionSummary = {
	session_id: "sess-plt46-001",
	turns: 4,
	started_at: "2026-09-06 00:00:00.000000",
	last_activity: "2026-09-06 00:05:00.000000",
	duration_us: 300_000_000,
	error_count: 0,
	status: "ok",
	cost_usd: 0.42,
	total_tokens: 1200,
	model: "claude-sonnet-4-5",
};

function renderRow(s: SessionSummary): string {
	return renderToStaticMarkup(createElement(SessionRow, { s, win: null }));
}

describe("sessions list — agent-name chip (PLT-46)", () => {
	it("renders a chip carrying the agent name when non-empty", () => {
		const html = renderRow({ ...BASE, agent_name: "claude-code" });
		expect(html).toContain("claude-code");
	});

	it("renders NO chip when agent_name is the field-not-yet-deployed case (absent)", () => {
		// BASE never sets `agent_name` — the exact shape a pre-deploy gateway
		// response has, since the field is `agent_name?: string`.
		const html = renderRow(BASE);
		expect(html).not.toContain("claude-code");
	});

	it('renders NO chip when agent_name is the deployed-but-empty case ("")', () => {
		const html = renderRow({ ...BASE, agent_name: "" });
		expect(html).not.toContain("claude-code");
	});

	it("still renders the session id link either way", () => {
		const withAgent = renderRow({ ...BASE, agent_name: "claude-code" });
		const withoutAgent = renderRow({ ...BASE, agent_name: "" });
		for (const html of [withAgent, withoutAgent]) {
			expect(html).toContain(`href="/sessions/${BASE.session_id}"`);
			expect(html).toContain(BASE.session_id);
		}
	});
});
