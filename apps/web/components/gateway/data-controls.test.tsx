// @vitest-environment jsdom
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { SlotView } from "./SlotView";
import { json, mockFetch, mount, when } from "./test-utils";

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});
const view = {
	retention: {
		days: null,
		effective_days: 730,
		plan_days: 730,
		min_days: 7,
		max_days: 730,
	},
	sweep: { mode: "off", enforced: false, next_sweep_at: null },
	capture: { input: false, output: false },
	key_overrides_count: 0,
	routes: [{ route: "Chat completions", binding: "gated" }],
};
const page = (
	<SlotView
		slot={{
			id: "data-controls",
			label: "Data controls",
			probe: "data-controls",
		}}
	/>
);

it("og38_data_controls_form_saves", async () => {
	const { calls } = mockFetch(
		when("GET", "/data-controls", () => json(view)),
		when("PUT", "/data-controls/retention", () =>
			json({ ...view, changed: true }),
		),
	);
	mount(page);
	fireEvent.change(await screen.findByLabelText("Retention (days)"), {
		target: { value: "90" },
	});
	fireEvent.change(screen.getByLabelText("Confirm deletion"), {
		target: { value: "delete data older than 90 days" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Save retention" }));
	await waitFor(() =>
		expect(calls.find((c) => c.method === "PUT")?.body).toEqual({
			days: 90,
			confirm: "delete data older than 90 days",
		}),
	);
});

it("og38_data_controls_denies_viewer_writes", async () => {
	mockFetch(when("GET", "/data-controls", () => json(view)));
	mount(page, "viewer");
	expect(
		(
			await screen.findByRole("button", { name: "Save retention" })
		).hasAttribute("disabled"),
	).toBe(true);
});

it("og38_data_controls_failed_save_visible", async () => {
	mockFetch(
		when("GET", "/data-controls", () => json(view)),
		when("PUT", "/data-controls/retention", () =>
			json(
				{
					error: "retention_unavailable",
					message: "Retention is temporarily unavailable",
				},
				503,
			),
		),
	);
	mount(page);
	fireEvent.change(await screen.findByLabelText("Retention (days)"), {
		target: { value: "90" },
	});
	fireEvent.change(screen.getByLabelText("Confirm deletion"), {
		target: { value: "delete data older than 90 days" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Save retention" }));
	expect(await screen.findByText(/temporarily unavailable/)).toBeTruthy();
	expect(
		(screen.getByLabelText("Retention (days)") as HTMLInputElement).value,
	).toBe("90");
});

it("og38_capture_panel_refreshes_saved_retention", async () => {
	let current = structuredClone(view);
	mockFetch(
		when("GET", "/data-controls", () => json(current)),
		when("GET", "/api/settings/content-capture", () =>
			json({
				input: true,
				output: true,
				operator_allowlisted: false,
				effective: { input: true, output: true },
				queryable_days: current.retention.effective_days,
				max_field_bytes: 65536,
				can_edit: true,
			}),
		),
		when("PUT", "/data-controls/retention", () => {
			current = {
				...current,
				retention: { ...current.retention, effective_days: 90 },
			};
			return json({ ...current, changed: true });
		}),
	);
	mount(page);
	expect(
		await screen.findByText(/for 730 days — the same as the trace/),
	).toBeTruthy();
	fireEvent.change(screen.getByLabelText("Retention (days)"), {
		target: { value: "90" },
	});
	fireEvent.change(screen.getByLabelText("Confirm deletion"), {
		target: { value: "delete data older than 90 days" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Save retention" }));
	expect(
		await screen.findByText(/for 90 days — the same as the trace/),
	).toBeTruthy();
});
