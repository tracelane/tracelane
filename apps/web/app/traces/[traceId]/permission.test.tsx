import type { ReactElement, ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it, vi } from "vitest";
vi.mock("@/lib/gateway", () => ({
	GatewayError: class extends Error {
		constructor(public status: number) {
			super("denied");
		}
	},
	gatewayGet: vi.fn(),
	gatewayGetOrNull: vi.fn(),
}));
import { GatewayError, gatewayGetOrNull } from "@/lib/gateway";
// The A+C merge (2026-10-01) gave the page three new imports; stubbed like the
// components below — this test is about the permission states, not those surfaces.
vi.mock("@/app/providers", () => ({
	Providers: ({ children }: { children: ReactNode }) => children,
}));
vi.mock("@/components/trace-viewer/IncidentPanel", () => ({
	IncidentPanel: () => null,
}));
vi.mock("@/lib/list-page-settings", () => ({
	getListPageSettings: async () => ({
		sizes: {
			experiments: 25,
			datasets: 100,
			experiment_datasets: 100,
			session_turns: 20,
			dataset_items: 50,
			trace_conversation_messages: 50,
			span_tool_names_preview: 10,
		},
		defaulted: true,
	}),
}));
vi.mock("@/components/trace-viewer/ChainStatusChip", () => ({
	ChainStatusChip: () => null,
}));
vi.mock("@/components/trace-viewer/TraceFlagPanel", () => ({
	TraceFlagPanel: () => null,
}));
vi.mock("@/components/trace-viewer/TraceHeaderActions", () => ({
	TraceHeaderActions: () => null,
}));
import Page from "./page";
function spanRead(
	node: ReactNode,
): ReactElement<{ traceId: string }> | undefined {
	if (!node || typeof node !== "object") return;
	if (Array.isArray(node)) {
		for (const child of node) {
			const found = spanRead(child);
			if (found) return found;
		}
		return;
	}
	const element = node as ReactElement<{
		children?: ReactNode;
		traceId?: string;
	}>;
	if (
		typeof element.type === "function" &&
		element.type.constructor.name === "AsyncFunction" &&
		element.props.traceId
	)
		return element as ReactElement<{ traceId: string }>;
	return spanRead(element.props?.children);
}
it("renders denied credentials as denied access, never unreachable trace storage", async () => {
	vi.mocked(gatewayGetOrNull).mockRejectedValue(
		new GatewayError(403, "denied"),
	);
	const page = await Page({ params: Promise.resolve({ traceId: "trace-id" }) });
	const read = spanRead(page);
	if (!read) throw new Error("missing asynchronous span read");
	const component = read.type as (props: {
		traceId: string;
	}) => Promise<ReactElement>;
	const html = renderToStaticMarkup(await component(read.props));
	expect(html).toContain("You don&#x27;t have access to trace data");
	expect(html).not.toContain("Waiting on trace storage");
});
