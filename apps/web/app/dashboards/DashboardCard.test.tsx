// @vitest-environment jsdom
/**
 * Tests for DashboardCard's rename affordance (2026-09-07).
 *
 * `PATCH /api/dashboards/[id]` (`apps/web/app/api/dashboards/[id]/route.ts`)
 * accepted a rename from day one, but the card's own doc comment claimed
 * "rename + delete actions" while no UI ever called it — a write API with no
 * caller. These tests assert the payload it sends matches exactly what that
 * route accepts (`{ name }`, trimmed) and that a server error reverts the
 * optimistic name change and surfaces the message, rather than silently
 * losing the edit.
 */

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DashboardCard } from "./DashboardCard";

const h = { refresh: vi.fn() };
vi.mock("next/navigation", () => ({
	useRouter: () => ({ refresh: h.refresh }),
}));

const dashboard = {
	id: "d1",
	name: "Original name",
	createdBy: "user_1",
	tileCount: 3,
	updatedAt: new Date(),
};

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
	h.refresh.mockClear();
});

function startRename() {
	fireEvent.click(
		screen.getByRole("button", { name: `Rename dashboard ${dashboard.name}` }),
	);
}

describe("DashboardCard rename — payload", () => {
	it("PATCHes /api/dashboards/[id] with exactly { name: <trimmed> } — the only field that route accepts", async () => {
		const fetchMock = vi.fn(
			async () =>
				new Response(JSON.stringify({ ...dashboard, name: "New name" }), {
					status: 200,
				}),
		);
		vi.stubGlobal("fetch", fetchMock);

		render(<DashboardCard dashboard={dashboard} canEdit={true} />);
		startRename();

		const input = screen.getByLabelText(`Rename dashboard "${dashboard.name}"`);
		fireEvent.change(input, { target: { value: "  New name  " } });
		fireEvent.click(screen.getByRole("button", { name: "Save" }));

		await screen.findByText("New name");

		expect(fetchMock).toHaveBeenCalledTimes(1);
		const call = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		const [url, init] = call;
		expect(url).toBe(`/api/dashboards/${dashboard.id}`);
		expect(init.method).toBe("PATCH");
		expect(JSON.parse(init.body as string)).toEqual({ name: "New name" });
		expect(h.refresh).toHaveBeenCalledTimes(1);
	});

	it("does not call the API when the trimmed name is unchanged", async () => {
		const fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);

		render(<DashboardCard dashboard={dashboard} canEdit={true} />);
		startRename();
		fireEvent.click(screen.getByRole("button", { name: "Save" }));

		expect(fetchMock).not.toHaveBeenCalled();
		expect(screen.getByText(dashboard.name)).toBeInTheDocument();
	});

	it("rejects an empty name locally, without calling the API", async () => {
		const fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);

		render(<DashboardCard dashboard={dashboard} canEdit={true} />);
		startRename();
		const input = screen.getByLabelText(`Rename dashboard "${dashboard.name}"`);
		fireEvent.change(input, { target: { value: "   " } });
		fireEvent.click(screen.getByRole("button", { name: "Save" }));

		expect(await screen.findByText("Name can't be empty")).toBeInTheDocument();
		expect(fetchMock).not.toHaveBeenCalled();
	});
});

describe("DashboardCard rename — server-error path", () => {
	it("reverts the name and shows the server's error message on a non-OK response", async () => {
		const fetchMock = vi.fn(
			async () =>
				new Response(
					JSON.stringify({ error: "name must be at most 60 characters" }),
					{
						status: 422,
					},
				),
		);
		vi.stubGlobal("fetch", fetchMock);

		render(<DashboardCard dashboard={dashboard} canEdit={true} />);
		startRename();
		const input = screen.getByLabelText(`Rename dashboard "${dashboard.name}"`);
		fireEvent.change(input, { target: { value: "x".repeat(61) } });
		fireEvent.click(screen.getByRole("button", { name: "Save" }));

		expect(
			await screen.findByText("name must be at most 60 characters"),
		).toBeInTheDocument();
		// Reverted — the original name is still shown, in the still-open edit input.
		expect(screen.getByDisplayValue(dashboard.name)).toBeInTheDocument();
		expect(h.refresh).not.toHaveBeenCalled();
	});

	it("reverts the name and shows a network-error message when fetch itself throws", async () => {
		const fetchMock = vi.fn(async () => {
			throw new Error("network down");
		});
		vi.stubGlobal("fetch", fetchMock);

		render(<DashboardCard dashboard={dashboard} canEdit={true} />);
		startRename();
		const input = screen.getByLabelText(`Rename dashboard "${dashboard.name}"`);
		fireEvent.change(input, { target: { value: "New name" } });
		fireEvent.click(screen.getByRole("button", { name: "Save" }));

		expect(
			await screen.findByText("Network error — try again"),
		).toBeInTheDocument();
		expect(screen.getByDisplayValue(dashboard.name)).toBeInTheDocument();
		expect(h.refresh).not.toHaveBeenCalled();
	});
});

describe("DashboardCard rename — visibility and keyboard", () => {
	it("the Rename button is not rendered when canEdit is false", () => {
		render(<DashboardCard dashboard={dashboard} canEdit={false} />);
		expect(
			screen.queryByRole("button", {
				name: `Rename dashboard ${dashboard.name}`,
			}),
		).not.toBeInTheDocument();
	});

	it("Escape cancels the edit and restores the last-saved name", () => {
		render(<DashboardCard dashboard={dashboard} canEdit={true} />);
		startRename();
		const input = screen.getByLabelText(`Rename dashboard "${dashboard.name}"`);
		fireEvent.change(input, { target: { value: "Abandoned edit" } });
		fireEvent.keyDown(input, { key: "Escape" });

		expect(screen.getByText(dashboard.name)).toBeInTheDocument();
		expect(screen.queryByText("Abandoned edit")).not.toBeInTheDocument();
	});
});
