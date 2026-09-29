// @vitest-environment jsdom
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { TraceFlag } from "./TraceFlag";
import { TraceHeaderActions } from "./TraceHeaderActions";
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
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
it("keeps one primary action and exposes every secondary verb in the menu", async () => {
	const copy = vi.fn().mockResolvedValue(undefined);
	vi.stubGlobal("navigator", { clipboard: { writeText: copy } });
	render(
		<TraceHeaderActions
			traceId="abc"
			flag={<TraceFlag traceId="abc" initial={null} canWrite embedded />}
		/>,
	);
	expect(screen.getByRole("button", { name: "Add to dataset" })).toBeTruthy();
	expect(screen.queryByRole("button", { name: "Copy ID" })).toBeNull();
	fireEvent.click(screen.getByRole("button", { name: "Trace actions" }));
	for (const name of [
		"Copy ID",
		"Copy link",
		"Compare",
		"Flag trace",
		"Share trace",
		"View ledger",
	])
		expect(screen.getByRole("menuitem", { name })).toBeTruthy();
	fireEvent.click(screen.getByRole("menuitem", { name: "Copy ID" }));
	await waitFor(() => expect(copy).toHaveBeenCalledWith("abc"));
	fireEvent.click(screen.getByRole("button", { name: "Trace actions" }));
	fireEvent.click(screen.getByRole("menuitem", { name: "Flag trace" }));
	expect(screen.getByRole("dialog", { name: "Flag trace" })).toBeTruthy();
	expect(screen.getByRole("button", { name: "Bad" })).toBeTruthy();
});
