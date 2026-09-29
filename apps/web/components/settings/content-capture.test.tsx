// @vitest-environment jsdom
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ContentCapture } from "./ContentCapture";
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
const settings = {
	input: true,
	output: true,
	operator_allowlisted: false,
	effective: { input: true, output: true },
	queryable_days: 30,
	max_field_bytes: 65536,
	can_edit: true,
};
const json = (data: unknown, status = 200) =>
	new Response(JSON.stringify(data), {
		status,
		headers: { "content-type": "application/json" },
	});
it("confirms stopping capture and preserves the server state when audit refuses", async () => {
	const fetch = vi
		.fn()
		.mockResolvedValueOnce(json(settings))
		.mockResolvedValueOnce(json({ error: "audit_unavailable" }, 503));
	vi.stubGlobal("fetch", fetch);
	render(<ContentCapture />);
	const toggle = await screen.findByRole("checkbox");
	fireEvent.click(toggle);
	expect(fetch).toHaveBeenCalledTimes(1);
	expect(
		screen.getByText("Text already recorded stays until its trace expires."),
	).toBeTruthy();
	fireEvent.click(screen.getByRole("button", { name: "Stop recording" }));
	await screen.findByText(
		"Not saved — the change could not be recorded in the audit ledger. Try again.",
	);
	expect((toggle as HTMLInputElement).checked).toBe(true);
	expect(JSON.parse(fetch.mock.calls[1]?.[1]?.body)).toEqual({
		input: false,
		output: false,
	});
});
it("does not dress a failed read as Off", async () => {
	vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({}, 503)));
	render(<ContentCapture />);
	await screen.findByText("Couldn't load this setting.");
	expect(screen.queryByRole("checkbox")).toBeNull();
});
it("cannot disable operator capture", async () => {
	vi.stubGlobal(
		"fetch",
		vi
			.fn()
			.mockResolvedValue(json({ ...settings, operator_allowlisted: true })),
	);
	render(<ContentCapture />);
	const toggle = await screen.findByRole("checkbox");
	expect((toggle as HTMLInputElement).disabled).toBe(true);
	expect(
		screen.getByText("Recording is on for this workspace by the operator."),
	).toBeTruthy();
});
