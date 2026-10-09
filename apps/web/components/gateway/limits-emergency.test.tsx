// @vitest-environment jsdom
/**
 * OG-60 §4 states, rendered, for Limits & budgets and Emergency: loading, empty, error is
 * NOT empty, forbidden, refused-at-the-field, role-gated control disabled WITH its reason,
 * and the exact body each write sends.
 */
import {
	cleanup,
	fireEvent,
	screen,
	waitFor,
	within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EmergencyControls } from "./EmergencyControls";
import { LimitsBudgets } from "./LimitsBudgets";
import { json, mockFetch, mount, openDialog, when } from "./test-utils";

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

const controls = (over: Record<string, unknown> = {}) => ({
	paused: false,
	pausedAt: null,
	pausedBy: null,
	pauseReason: null,
	blocks: { models: [], providers: [], endUsers: [] },
	policy: null,
	updatedAt: null,
	...over,
});

describe("Limits & budgets", () => {
	it("loading is a skeleton, not an empty claim", () => {
		mockFetch(() => new Promise<Response>(() => {}) as never);
		mount(<LimitsBudgets />);
		expect(screen.getAllByLabelText("Loading").length).toBeGreaterThan(0);
		expect(screen.queryByText(/not restricted/)).toBeNull();
	});

	it("empty says the consequence; no counters says when one appears", async () => {
		mockFetch(
			when("GET", "/controls", () => json(controls())),
			when("GET", "/controls/budgets", () => json({ budgets: [] })),
		);
		mount(<LimitsBudgets />);
		expect(
			await screen.findByText(/traffic is not restricted at this layer/),
		).toBeTruthy();
		expect(
			await screen.findByText(/No budget counters on this gateway/),
		).toBeTruthy();
	});

	it("a failed read is an error with its status, never the empty copy", async () => {
		mockFetch(
			when("GET", "/controls", () =>
				json({ error: "gateway_unavailable" }, 502),
			),
			when("GET", "/controls/budgets", () => json({ budgets: [] })),
		);
		mount(<LimitsBudgets />);
		expect(
			await screen.findByText(/Couldn't load the workspace policy/),
		).toBeTruthy();
		expect(screen.getByText(/HTTP 502/)).toBeTruthy();
		expect(
			screen.queryByText(/traffic is not restricted at this layer/),
		).toBeNull();
	});

	it("a role 403 on read says who may", async () => {
		mockFetch(
			when("GET", "/controls", () =>
				json({ error: "role_forbidden", required_role: "viewer" }, 403),
			),
			when("GET", "/controls/budgets", () => json({ budgets: [] })),
		);
		mount(<LimitsBudgets />, null);
		expect(
			await screen.findByText(/You can't view the workspace policy/),
		).toBeTruthy();
	});

	it("an unknown spend renders 'unknown', never $0", async () => {
		mockFetch(
			when("GET", "/controls", () => json(controls())),
			when("GET", "/controls/budgets", () =>
				json({
					budgets: [
						{
							policy: "workspace",
							scope: "workspace",
							subjectId: null,
							endUser: null,
							window: "monthly",
							mode: "hard",
							budgetUsd: 100,
							spentUsd: null,
							known: false,
							resetsAt: "2026-11-01T00:00:00Z",
						},
					],
				}),
			),
		);
		mount(<LimitsBudgets />);
		expect(await screen.findByText("unknown")).toBeTruthy();
		expect(screen.queryByText("$0.00")).toBeNull();
		expect(screen.getByText("Nov 1, 2026 · 00:00 UTC")).toBeTruthy();
	});

	it("saves exactly the typed policy, and shows the gateway's field refusal", async () => {
		const f = mockFetch(
			when("GET", "/controls", () => json(controls())),
			when("GET", "/controls/budgets", () => json({ budgets: [] })),
			when("PUT", "/controls/policy", () =>
				json(
					{
						error: "invalid_field",
						field: "policy.limits.rpm",
						message: "rpm is above the maximum",
					},
					400,
				),
			),
		);
		mount(<LimitsBudgets />);
		const rpm = await screen.findByLabelText("Requests / min");
		fireEvent.change(rpm, { target: { value: "99999999999" } });
		fireEvent.click(
			screen.getByRole("button", { name: "Save workspace policy" }),
		);
		await waitFor(() =>
			expect(
				screen.getAllByText("rpm is above the maximum").length,
			).toBeGreaterThan(0),
		);
		const put = f.calls.find((c) => c.method === "PUT");
		expect(put?.body).toEqual({ policy: { limits: { rpm: 99999999999 } } });
	});

	it("a viewer sees the values but every control is disabled, with the reason", async () => {
		mockFetch(
			when("GET", "/controls", () =>
				json(controls({ policy: { limits: { rpm: 60 } } })),
			),
			when("GET", "/controls/budgets", () => json({ budgets: [] })),
		);
		mount(<LimitsBudgets />, "viewer");
		const rpm = (await screen.findByLabelText(
			"Requests / min",
		)) as HTMLInputElement;
		expect(rpm.value).toBe("60");
		expect(rpm.disabled).toBe(true);
		expect(
			(
				screen.getByRole("button", {
					name: "Save workspace policy",
				}) as HTMLButtonElement
			).disabled,
		).toBe(true);
		expect(screen.getByTestId("why-disabled").textContent).toMatch(
			/owner or admin/,
		);
	});
});

describe("Emergency controls", () => {
	it("pause needs the confirm dialog, and sends the reason", async () => {
		const f = mockFetch(
			when("GET", "/controls", () => json(controls())),
			when("POST", "/controls/pause", () => json(controls({ paused: true }))),
		);
		mount(<EmergencyControls />);
		fireEvent.click(
			await screen.findByRole("button", { name: "Pause workspace" }),
		);
		expect(f.calls.some((c) => c.method === "POST")).toBe(false);
		const dialog = openDialog();
		fireEvent.change(within(dialog).getByLabelText(/Reason/), {
			target: { value: "key leaked" },
		});
		fireEvent.click(
			within(dialog).getByRole("button", { name: "Pause workspace" }),
		);
		await waitFor(() =>
			expect(f.calls.find((c) => c.method === "POST")?.body).toEqual({
				reason: "key leaked",
			}),
		);
	});

	it("a paused workspace shows who and why, and offers Resume", async () => {
		mockFetch(
			when("GET", "/controls", () =>
				json(
					controls({
						paused: true,
						pausedAt: "2026-10-05T08:00:00Z",
						pausedBy: "user_01",
						pauseReason: "runaway agent",
					}),
				),
			),
		);
		mount(<EmergencyControls />);
		expect(await screen.findByText(/runaway agent/)).toBeTruthy();
		expect(screen.getByText(/by user_01/)).toBeTruthy();
		expect(
			screen.getByRole("button", { name: "Resume workspace" }),
		).toBeTruthy();
		expect(
			screen.queryByRole("button", { name: "Pause workspace" }),
		).toBeNull();
	});

	it("revoke-all is blocked until the gateway's phrase is typed", async () => {
		const f = mockFetch(
			when("GET", "/controls", () => json(controls())),
			when("POST", "/controls/revoke-all-keys", () =>
				json({ revoked: 3, keyIds: ["a", "b", "c"] }),
			),
		);
		mount(<EmergencyControls />);
		fireEvent.click(
			await screen.findByRole("button", { name: "Revoke all keys…" }),
		);
		const dialog = openDialog();
		const confirm = within(dialog).getByRole("button", {
			name: "Revoke all keys",
		}) as HTMLButtonElement;
		expect(confirm.disabled).toBe(true);
		fireEvent.change(within(dialog).getByLabelText("Confirmation name"), {
			target: { value: "revoke all keys" },
		});
		expect(confirm.disabled).toBe(false);
		fireEvent.click(confirm);
		await waitFor(() =>
			expect(f.calls.find((c) => c.method === "POST")?.body).toEqual({
				confirm: "revoke all keys",
			}),
		);
		expect(await screen.findByText("Revoked 3 keys.")).toBeTruthy();
	});

	it("a developer sees the controls disabled with the reason, not hidden", async () => {
		mockFetch(when("GET", "/controls", () => json(controls())));
		mount(<EmergencyControls />, "developer");
		const pause = (await screen.findByRole("button", {
			name: "Pause workspace",
		})) as HTMLButtonElement;
		expect(pause.disabled).toBe(true);
		const revoke = screen.getByRole("button", {
			name: "Revoke all keys…",
		}) as HTMLButtonElement;
		expect(revoke.disabled).toBe(true);
		expect(screen.getAllByTestId("why-disabled").length).toBeGreaterThan(0);
	});

	it("saves each block list as typed; an empty set says nothing is blocked", async () => {
		const f = mockFetch(
			when("GET", "/controls", () => json(controls())),
			when("PUT", "/controls/blocks", () => json(controls())),
		);
		mount(<EmergencyControls />);
		expect(await screen.findByText(/Nothing is blocked/)).toBeTruthy();
		fireEvent.change(screen.getByLabelText(/Blocked models/), {
			target: { value: "gpt-4o\n\n claude-* " },
		});
		fireEvent.click(screen.getByRole("button", { name: "Save block lists" }));
		await waitFor(() =>
			expect(f.calls.find((c) => c.method === "PUT")?.body).toEqual({
				models: ["gpt-4o", "claude-*"],
				providers: [],
				endUsers: [],
			}),
		);
	});

	it("an admin-IP refusal is worded as that, not as a generic failure", async () => {
		mockFetch(
			when("GET", "/controls", () => json(controls())),
			when("POST", "/controls/pause", () =>
				json({ error: "admin_ip_not_allowed" }, 403),
			),
		);
		mount(<EmergencyControls />);
		fireEvent.click(
			await screen.findByRole("button", { name: "Pause workspace" }),
		);
		const dialog = openDialog();
		fireEvent.click(
			within(dialog).getByRole("button", { name: "Pause workspace" }),
		);
		expect(
			await screen.findByText(/restricts admin actions to an IP allowlist/),
		).toBeTruthy();
	});
});

describe("budget counter subject column", () => {
	it("shortens a UUID subject to 8 characters and keeps the rest out of the cell", async () => {
		const { shortId } = await import("./LimitsBudgets");
		expect(shortId("7a1c0f0e-1111-4a11-8a11-000000000a01")).toBe("7a1c0f0e…");
		expect(shortId("workspace")).toBe("workspace");
		expect(shortId("end-user-42")).toBe("end-user-42");
	});
});
