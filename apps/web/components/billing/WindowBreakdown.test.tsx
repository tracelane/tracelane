// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { WindowBreakdown } from "./WindowBreakdown";
const { apiFetchRaw } = vi.hoisted(() => ({ apiFetchRaw: vi.fn() }));
vi.mock("@/lib/api-fetch", () => ({ apiFetchRaw }));
afterEach(cleanup);
it("renders real byte rows and offers key/service with honest empty labels", async () => {
	apiFetchRaw.mockImplementation(async (url: string) => ({
		ok: true,
		json: async () => ({
			by: url.includes("by=key") ? "key" : "service",
			rows: [
				{ key: "", bytes: 1_000_000_000 },
				{ key: "checkout", bytes: 3_000_000_000 },
			],
			total_bytes: 4_000_000_000,
			truncated: true,
		}),
	}));
	render(<WindowBreakdown />);
	expect(await screen.findByText("checkout")).toBeTruthy();
	expect(screen.getByText("(not set)")).toBeTruthy();
	expect(screen.getByText("1.0 GB · 25%")).toBeTruthy();
	expect(screen.queryByText("project")).toBeNull();
	fireEvent.click(screen.getByRole("button", { name: "API key" }));
	expect(await screen.findByText("Dashboard session (no key)")).toBeTruthy();
	expect(screen.getByRole("button", { name: "service" })).toBeTruthy();
	expect(screen.getByText(/row limit/)).toBeTruthy();
	expect(screen.queryByText(/of undefined/)).toBeNull();
});
it("renders empty and failed queries without invented usage", async () => {
	apiFetchRaw.mockResolvedValue({
		ok: true,
		json: async () => ({
			by: "capture",
			rows: [],
			total_bytes: 0,
			truncated: false,
		}),
	});
	const view = render(<WindowBreakdown />);
	expect(
		await screen.findByText(/Nothing in your indexed window/),
	).toBeTruthy();
	view.unmount();
	apiFetchRaw.mockResolvedValue({ ok: false });
	render(<WindowBreakdown />);
	expect(await screen.findByText(/Could not load the breakdown/)).toBeTruthy();
});
