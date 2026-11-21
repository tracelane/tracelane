// @vitest-environment jsdom
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ActionControlSetting } from "./ActionControlSetting";

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
const state = (o = {}) => ({
	enabled: false,
	can_edit: true,
	note: "Usually takes effect within 15 minutes.",
	off_warning: "Protected tools fall back to the standard per-tool rules.",
	...o,
});
const json = (d: unknown, status = 200) =>
	new Response(JSON.stringify(d), {
		status,
		headers: { "content-type": "application/json" },
	});

it("leads with the state and never shows an internal id", async () => {
	vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(state())));
	const { container } = render(<ActionControlSetting />);
	await screen.findByText("Action control is off for this workspace.");
	expect(container.textContent).not.toMatch(/\b(ACT|SRE|ADR)-\d+|tenant|org_/i);
});
it("a non-owner sees read-only state and the owner-only line", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn().mockResolvedValue(json(state({ can_edit: false }))),
	);
	render(<ActionControlSetting />);
	const box = await screen.findByRole("checkbox");
	expect((box as HTMLInputElement).disabled).toBe(true);
	expect(
		screen.getByText("Only workspace owners and admins can change this."),
	).toBeTruthy();
});
it("turning on asks for confirmation before any write, then sends confirmed", async () => {
	const fetch = vi
		.fn()
		.mockResolvedValueOnce(json(state()))
		.mockResolvedValueOnce(json({ enabled: true, changed: true, note: "N" }));
	vi.stubGlobal("fetch", fetch);
	render(<ActionControlSetting />);
	fireEvent.click(await screen.findByRole("checkbox"));
	expect(fetch).toHaveBeenCalledTimes(1);
	fireEvent.click(screen.getByRole("button", { name: "Turn on" }));
	await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
	expect(JSON.parse(fetch.mock.calls[1]?.[1]?.body)).toEqual({
		enabled: true,
		confirmed: true,
	});
	await screen.findByText("Action control is on for this workspace.");
});
it("turning off shows the warning first and writes nothing until confirmed", async () => {
	const fetch = vi.fn().mockResolvedValueOnce(json(state({ enabled: true })));
	vi.stubGlobal("fetch", fetch);
	render(<ActionControlSetting />);
	fireEvent.click(await screen.findByRole("checkbox"));
	expect(screen.getByText(/standard per-tool rules/)).toBeTruthy();
	expect(fetch).toHaveBeenCalledTimes(1);
});
it("a refused save keeps the old state and says so", async () => {
	const fetch = vi
		.fn()
		.mockResolvedValueOnce(json(state()))
		.mockResolvedValueOnce(json({ error: "control_audit_unavailable" }, 503));
	vi.stubGlobal("fetch", fetch);
	render(<ActionControlSetting />);
	fireEvent.click(await screen.findByRole("checkbox"));
	fireEvent.click(screen.getByRole("button", { name: "Turn on" }));
	await screen.findAllByText(/Not saved/);
	expect(
		screen.queryByText("Action control is on for this workspace."),
	).toBeNull();
});
it("a failed read shows an error with retry, not a false state", async () => {
	vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({}, 503)));
	render(<ActionControlSetting />);
	await screen.findByText("Couldn't load this setting.");
	expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy();
});
