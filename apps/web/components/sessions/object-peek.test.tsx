import type { SessionSummary } from "@/lib/sessions";
// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { SessionRow } from "./SessionRow";
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
	window.history.replaceState(null, "", "/sessions");
});
Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
	configurable: true,
	value: function () {
		this.setAttribute("open", "");
	},
});
Object.defineProperty(HTMLDialogElement.prototype, "close", {
	configurable: true,
	value: function () {
		this.removeAttribute("open");
	},
});
const row: SessionSummary = {
	session_id: "alpha",
	turns: 2,
	started_at: "2026-09-28 01:00:00",
	last_activity: "2026-09-28 01:02:00",
	duration_us: 120000000,
	error_count: 0,
	status: "ok",
	cost_usd: 0.1,
	total_tokens: 100,
	model: "test",
};
it("navigates object rows and opens a URL peek without fetching", () => {
	const fetch = vi.fn();
	vi.stubGlobal("fetch", fetch);
	window.history.replaceState(null, "", "/sessions?range=all");
	render(
		<table>
			<tbody>
				<SessionRow s={row} win={null} />
				<SessionRow s={{ ...row, session_id: "beta" }} win={null} />
			</tbody>
		</table>,
	);
	const rows = screen.getAllByRole("row");
	if (!rows[0] || !rows[1]) throw new Error("Expected two session rows");
	rows[0].focus();
	fireEvent.keyDown(rows[0], { key: "j" });
	expect(document.activeElement).toBe(rows[1]);
	fireEvent.keyDown(rows[1], { key: "Enter" });
	expect(window.location.search).toBe("?range=all&peek=beta");
	expect(screen.getByRole("dialog", { name: "beta" })).toBeTruthy();
	expect(fetch).not.toHaveBeenCalled();
	fireEvent(
		screen.getByRole("dialog"),
		new Event("cancel", { bubbles: true, cancelable: true }),
	);
	expect(screen.queryByRole("dialog")).toBeNull();
	expect(window.location.search).toBe("?range=all");
	fireEvent.contextMenu(rows[0]);
	expect(screen.getByRole("menuitem", { name: "Peek" })).toBeTruthy();
	fireEvent.click(screen.getByRole("menuitem", { name: "Peek" }));
	expect(screen.getByRole("dialog", { name: "alpha" })).toBeTruthy();
});
it("preserves native context menus on links and editable controls", () => {
	render(
		<table>
			<tbody>
				<SessionRow s={row} win={null} />
			</tbody>
		</table>,
	);
	const link = screen.getByRole("link", { name: "alpha" });
	const event = new MouseEvent("contextmenu", {
		bubbles: true,
		cancelable: true,
	});
	fireEvent(link, event);
	expect(event.defaultPrevented).toBe(false);
	expect(screen.queryByRole("menu")).toBeNull();
});
it("renders peek status with the shared badge vocabulary", () => {
	render(
		<table>
			<tbody>
				<SessionRow s={row} win={null} />
			</tbody>
		</table>,
	);
	fireEvent.keyDown(screen.getByRole("row"), { key: "Enter" });
	expect(screen.getByRole("dialog").textContent).toContain("StatusOK");
});
it.each(["button", "input", "textarea", "select", "div"])(
	"preserves native context menus for row %s controls",
	(tag) => {
		render(
			<table>
				<tbody>
					<SessionRow s={row} win={null} />
				</tbody>
			</table>,
		);
		const control = document.createElement(tag);
		if (tag === "div") control.setAttribute("contenteditable", "true");
		const cell = document.createElement("td");
		cell.append(control);
		screen.getByRole("row").append(cell);
		const event = new MouseEvent("contextmenu", {
			bubbles: true,
			cancelable: true,
		});
		fireEvent(control, event);
		expect(event.defaultPrevented).toBe(false);
		expect(screen.queryByRole("menu")).toBeNull();
	},
);
