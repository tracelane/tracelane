// @vitest-environment jsdom
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
vi.mock("@/lib/gateway", () => ({ gatewayGetOrNull: vi.fn() }));
import { ChainStatusChip } from "@/components/trace-viewer/ChainStatusChip";
import { gatewayGetOrNull } from "@/lib/gateway";
import { LedgerCoverage } from "./LedgerCoverage";
afterEach(cleanup);
it.each([false, true])(
	"labels stored chain membership explicitly (%s)",
	async (chained) => {
		vi.mocked(gatewayGetOrNull).mockResolvedValue({
			chained,
			seq: chained ? 7 : null,
			anchored: false,
		});
		render(await ChainStatusChip({ traceId: "trace" }));
		expect(
			screen.getByText(chained ? "In the ledger" : "Captured, not chained", {
				exact: false,
			}),
		).toBeTruthy();
		expect(gatewayGetOrNull).toHaveBeenLastCalledWith("/v1/traces/trace/chain");
	},
);
it("does not infer capture origin or membership when the endpoint is unavailable", async () => {
	vi.mocked(gatewayGetOrNull).mockResolvedValue(null);
	render(await ChainStatusChip({ traceId: "trace" }));
	expect(screen.getByText("Ledger status unavailable")).toBeTruthy();
	expect(screen.queryByText("Captured, not chained")).toBeNull();
});
it("states the capture boundary on the page and keeps the documentation consistent", () => {
	render(<LedgerCoverage />);
	expect(screen.getByText("Chained:")).toBeTruthy();
	expect(screen.getByText("Captured, not chained:")).toBeTruthy();
	expect(screen.getByText(/SDK\/OTLP-only spans/)).toBeTruthy();
	expect(readFileSync(resolve("../docs/audit-ledger.mdx"), "utf8")).toContain(
		"SDK/OTLP-only spans are captured, not chained",
	);
});

it("keeps membership explicit when an anchor is recorded", async () => {
	vi.mocked(gatewayGetOrNull).mockResolvedValue({
		chained: true,
		seq: 7,
		anchored: true,
	});
	render(await ChainStatusChip({ traceId: "trace" }));
	expect(
		screen.getByText("In the ledger · Anchor recorded", { exact: false }),
	).toBeTruthy();
	expect(screen.getByRole("link").getAttribute("href")).toBe("/audit");
});
it("renders transport failure as unknown rather than unchained", async () => {
	vi.mocked(gatewayGetOrNull).mockRejectedValue(new Error("offline"));
	render(await ChainStatusChip({ traceId: "trace" }));
	expect(screen.getByText("Ledger status unavailable")).toBeTruthy();
});

// Optional local integration proof: the file contains span rows read from the
// store and each trace's real /chain response. Unit runs never contact a service.
it.skipIf(!process.env.LEDGER_STORED_ROWS)(
	"renders gateway and OTLP membership from local stored-row readback",
	async () => {
		const rows = JSON.parse(
			readFileSync(process.env.LEDGER_STORED_ROWS ?? "", "utf8"),
		) as Array<{
			trace_id: string;
			name: string;
			chain: { chained: boolean; seq: number | null; anchored: boolean };
		}>;
		expect(rows).toHaveLength(3);
		const { container } = render(<LedgerCoverage />);
		for (const name of [
			"gen_ai.chat",
			"gen_ai.embeddings",
			"otlp-only-proof",
		]) {
			const row = rows.find((r) => r.name === name);
			expect(row).toBeDefined();
			if (!row) throw new Error(`Missing stored row: ${name}`);
			expect(row.chain.chained).toBe(name !== "otlp-only-proof");
			vi.mocked(gatewayGetOrNull).mockResolvedValue(row.chain);
			const badge = render(await ChainStatusChip({ traceId: row.trace_id }));
			expect(
				within(badge.container).getByText(
					name !== "otlp-only-proof"
						? "In the ledger"
						: "Captured, not chained",
					{ exact: false },
				),
			).toBeTruthy();
			expect(gatewayGetOrNull).toHaveBeenLastCalledWith(
				`/v1/traces/${row.trace_id}/chain`,
			);
			container.append(badge.container);
		}
		if (process.env.LEDGER_RENDER_HTML) {
			writeFileSync(
				process.env.LEDGER_RENDER_HTML,
				`<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1" /></head><body><main style="padding:20px"><h1>Audit ledger coverage</h1>${container.innerHTML}</main></body></html>`,
			);
		}
	},
);
