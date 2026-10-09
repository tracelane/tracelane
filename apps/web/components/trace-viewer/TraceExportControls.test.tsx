// @vitest-environment jsdom
import { apiFetchRaw } from "@/lib/api-fetch";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { TraceExportControls } from "./TraceExportControls";

vi.mock("@/lib/api-fetch", () => ({ apiFetchRaw: vi.fn() }));
beforeEach(() => {
	Object.defineProperty(URL, "createObjectURL", {
		value: vi.fn(() => "blob:export"),
		configurable: true,
	});
	Object.defineProperty(URL, "revokeObjectURL", {
		value: vi.fn(),
		configurable: true,
	});
	vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
});
afterEach(() => {
	cleanup();
	vi.resetAllMocks();
});

it("downloads a capped file and resumes with its cursor and pinned window", async () => {
	vi.mocked(apiFetchRaw)
		.mockResolvedValueOnce(
			new Response("trace_id\nt1\n", {
				headers: {
					"x-tracelane-truncated": "true",
					"x-tracelane-row-count": "10000",
					"x-tracelane-next-cursor": "90:t2",
				},
			}),
		)
		.mockResolvedValueOnce(
			new Response("trace_id\nt3\n", {
				headers: {
					"x-tracelane-truncated": "false",
					"x-tracelane-row-count": "1",
				},
			}),
		);
	render(
		<TraceExportControls
			baseQuery="q=needle&failover=true"
			windowQuery="since=2026-09-29T00%3A00%3A00Z&until=2026-09-30T00%3A00%3A00Z"
		/>,
	);
	fireEvent.click(screen.getByRole("button", { name: "Export CSV" }));
	expect(
		await screen.findByText("Exported 10,000 rows — more remain"),
	).toBeTruthy();
	fireEvent.click(screen.getByRole("button", { name: "Export next 10,000" }));
	expect(await screen.findByText("Exported 1 row")).toBeTruthy();
	const calls = vi.mocked(apiFetchRaw).mock.calls;
	const first = new URL(calls[0]?.[0] ?? "", "http://app.test");
	const second = new URL(calls[1]?.[0] ?? "", "http://app.test");
	expect(first.searchParams.get("q")).toBe("needle");
	expect(second.searchParams.get("cursor")).toBe("90:t2");
	expect(second.searchParams.get("until")).toBe(
		first.searchParams.get("until"),
	);
});

it("does not invent a zero row count when a response omits the count header", async () => {
	vi.mocked(apiFetchRaw).mockResolvedValue(new Response("trace_id\n"));
	render(
		<TraceExportControls
			baseQuery=""
			windowQuery="since=2026-09-29T00%3A00%3A00Z&until=2026-09-30T00%3A00%3A00Z"
		/>,
	);
	fireEvent.click(screen.getByRole("button", { name: "Export CSV" }));
	expect(await screen.findByText("Exported trace file")).toBeTruthy();
});

it("keeps the page usable after an export error", async () => {
	vi.mocked(apiFetchRaw).mockResolvedValue(new Response("", { status: 502 }));
	render(
		<TraceExportControls
			baseQuery=""
			windowQuery="since=2026-09-29T00%3A00%3A00Z&until=2026-09-30T00%3A00%3A00Z"
		/>,
	);
	fireEvent.click(screen.getByRole("button", { name: "Export CSV" }));
	expect(await screen.findByRole("alert")).toHaveProperty(
		"textContent",
		expect.stringContaining("Export failed — try a narrower range"),
	);
	expect(
		screen.getByRole("button", { name: "Export CSV" }).hasAttribute("disabled"),
	).toBe(false);
});
