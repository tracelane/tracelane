/**
 * B-520 (CX-21) — `/review`'s "New queue" cap must be derived from ACTIVE
 * queues only, never from the raw list length. The gateway's create cap
 * (`crates/gateway/src/annotation_routes.rs:644`, `MAX_QUEUES = 50`) counts
 * active queues; the list endpoint returns active rows first (ordered NULLS
 * FIRST) and fills the remainder of its 50-row LIMIT with archived ones. A
 * tenant with 30 active + 20 archived queues sees a list of length 50 and,
 * before this fix, was told "You have 50 active queues (the maximum)" —
 * wrong on both counts: there are 30, not 50, and the gateway would still
 * accept a create.
 *
 * Mocking pattern follows `apps/web/app/playground/page.test.tsx`: `@/lib/
 * gateway` is mocked wholesale (never a real network,
 * `.claude/rules/testing.md`), and `next/navigation` + `next/link` are
 * mocked because `NewQueueDialog` and `QueueRow` are client components that
 * call `useRouter()` unconditionally and render a real `<Link>`.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("next/link", () => ({
	default: ({ href, children, ...rest }: Record<string, unknown>) =>
		createElement("a", { href, ...rest }, children as never),
}));

vi.mock("next/navigation", () => ({
	useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
}));

const h = vi.hoisted(() => ({ gatewayGet: vi.fn() }));

vi.mock("@/lib/gateway", () => ({
	gatewayGet: (...args: unknown[]) => h.gatewayGet(...(args as [string])),
	GatewayError: class FakeGatewayError extends Error {
		status: number;
		constructor(status: number, message: string) {
			super(message);
			this.status = status;
		}
	},
}));

import type { AnnotationQueue } from "@/app/api/annotation-queues/shared";
import ReviewQueuesPage from "./page";

function makeQueue(
	id: string,
	overrides: Partial<AnnotationQueue> = {},
): AnnotationQueue {
	return {
		id,
		name: `Queue ${id}`,
		filter: { source: { kind: "trace_error" }, window_hours: 168 },
		rubric: [],
		default_dataset_id: "ds-1",
		expected_output_field: "expected_answer",
		created_by: "e2e@tracelane.test",
		created_at: "2026-09-01T00:00:00Z",
		updated_at: "2026-09-01T00:00:00Z",
		...overrides,
	};
}

function mockQueuesAndDatasets(queues: AnnotationQueue[], maxQueues: number) {
	h.gatewayGet.mockImplementation(async (path: string) => {
		if (path === "/v1/annotation-queues") {
			return { queues, max_queues: maxQueues };
		}
		if (path === "/v1/datasets") {
			return { datasets: [{ dataset_id: "ds-1", name: "Support replies" }] };
		}
		throw new Error(`unexpected gatewayGet(${path})`);
	});
}

beforeEach(() => {
	h.gatewayGet.mockReset();
});

describe("B-520 — New-queue cap counts ACTIVE queues, not the raw list length", () => {
	it("does not disable New queue when archived rows fill the list up to max_queues but active count is below it", async () => {
		const active = Array.from({ length: 30 }, (_, i) => makeQueue(`a${i}`));
		const archived = Array.from({ length: 20 }, (_, i) =>
			makeQueue(`r${i}`, { archived_at: "2026-09-10T00:00:00Z" }),
		);
		// 30 active + 20 archived = 50, exactly max_queues — the shape that
		// tripped the old `queues.length >= max_queues` check.
		mockQueuesAndDatasets([...active, ...archived], 50);

		const el = await ReviewQueuesPage();
		const html = renderToStaticMarkup(el);

		expect(html).not.toContain('data-testid="nq-disabled-reason"');
		expect(html).not.toMatch(/active queues \(the maximum\)/);
	});

	it("states the REAL active count in the cap message when it differs from max_queues, not max_queues itself", async () => {
		// 52 active queues, 0 archived, cap 50 — both the old and new atCap
		// formula agree the control should disable, but the old message
		// printed `maxQueues` (50) as if that were the count the tenant has.
		const active = Array.from({ length: 52 }, (_, i) => makeQueue(`a${i}`));
		mockQueuesAndDatasets(active, 50);

		const el = await ReviewQueuesPage();
		const html = renderToStaticMarkup(el);

		expect(html).toContain("You have 52 active queues");
		expect(html).not.toContain("You have 50 active queues");
	});

	it("still disables New queue, at the real active count, when active queues alone reach the cap", async () => {
		const active = Array.from({ length: 50 }, (_, i) => makeQueue(`a${i}`));
		mockQueuesAndDatasets(active, 50);

		const el = await ReviewQueuesPage();
		const html = renderToStaticMarkup(el);

		expect(html).toContain('data-testid="nq-disabled-reason"');
		expect(html).toContain("You have 50 active queues");
	});
});
