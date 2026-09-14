// @vitest-environment jsdom
/**
 * OBS-01 proof #2 (client half): typing below the 4-character minimum never
 * submits — no URL change, the inline hint shows — and a valid term submits
 * on Enter. `next/navigation` is mocked locally (overriding the vitest-config
 * global stub) so `router.replace` is a spy and `useSearchParams` is
 * controllable per test.
 */

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	replace: vi.fn(),
	params: new URLSearchParams(),
}));

vi.mock("next/navigation", () => ({
	useRouter: () => ({ replace: h.replace }),
	usePathname: () => "/traces",
	useSearchParams: () => h.params,
}));

import { FilterBar } from "./FilterBar";

function searchInput(): HTMLInputElement {
	return screen.getByPlaceholderText(
		/search span names and attributes/i,
	) as HTMLInputElement;
}

beforeEach(() => {
	h.replace.mockClear();
	h.params = new URLSearchParams();
});

// No global `setupFiles` registers RTL's auto-cleanup in this repo's vitest
// config — without this, each `render()` mounts on TOP of the previous
// test's DOM and `getByPlaceholderText` starts matching more than one node.
afterEach(cleanup);

describe("FilterBar search box", () => {
	it("does not submit below the 4-character minimum, and shows the inline hint", () => {
		render(<FilterBar />);
		fireEvent.change(searchInput(), { target: { value: "abc" } });
		fireEvent.keyDown(searchInput(), { key: "Enter" });

		expect(h.replace).not.toHaveBeenCalled();
		expect(screen.getByText("4 characters minimum")).toBeInTheDocument();
	});

	it('does not show the hint below 1 character (empty is not "too short", it\'s just empty)', () => {
		render(<FilterBar />);
		fireEvent.change(searchInput(), { target: { value: "" } });
		expect(screen.queryByText("4 characters minimum")).not.toBeInTheDocument();
	});

	it("submits a 4+ character term on Enter", () => {
		render(<FilterBar />);
		fireEvent.change(searchInput(), { target: { value: "claude" } });
		fireEvent.keyDown(searchInput(), { key: "Enter" });

		expect(h.replace).toHaveBeenCalledTimes(1);
		expect(h.replace).toHaveBeenCalledWith("/traces?q=claude");
	});

	it("Escape clears the box and the committed q param", () => {
		h.params = new URLSearchParams("q=claude");
		render(<FilterBar />);
		expect(searchInput().value).toBe("claude");

		fireEvent.keyDown(searchInput(), { key: "Escape" });

		expect(h.replace).toHaveBeenCalledWith("/traces");
	});

	it("a 3-character term never reaches the URL even across multiple Enters", () => {
		render(<FilterBar />);
		for (const term of ["a", "ab", "abc"]) {
			fireEvent.change(searchInput(), { target: { value: term } });
			fireEvent.keyDown(searchInput(), { key: "Enter" });
		}
		expect(h.replace).not.toHaveBeenCalled();
	});
});
