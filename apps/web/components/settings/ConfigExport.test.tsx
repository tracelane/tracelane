// @vitest-environment jsdom
/** The configuration download: it saves a dated file, words a 403, and offers a retry. */
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ConfigExport, exportFileName } from "./ConfigExport";

const saved: { name: string; text: string }[] = [];

beforeEach(() => {
	saved.length = 0;
	// jsdom's Blob cannot be read back portably, so record what the component builds.
	class RecordingBlob {
		constructor(
			public parts: string[],
			public options: unknown,
		) {}
	}
	let last: RecordingBlob | undefined;
	vi.stubGlobal("Blob", RecordingBlob);
	vi.stubGlobal("URL", {
		...URL,
		createObjectURL: (b: RecordingBlob) => {
			last = b;
			return "blob:fixture";
		},
		revokeObjectURL: () => {},
	});
	vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
		this: HTMLAnchorElement,
	) {
		saved.push({ name: this.download, text: (last?.parts ?? []).join("") });
	});
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

const press = () =>
	fireEvent.click(
		screen.getByRole("button", { name: "Download configuration" }),
	);

it("config_dashboard_downloads_export: saves the document under a UTC-dated name", async () => {
	const doc = { schema: "tracelane.config/v1", version: "abc", sections: {} };
	const f = vi.fn(async () => Response.json(doc));
	vi.stubGlobal("fetch", f);
	render(<ConfigExport />);
	press();
	await waitFor(() => expect(saved).toHaveLength(1));
	expect(f).toHaveBeenCalledWith("/api/settings/config-export", {
		cache: "no-store",
	});
	expect(saved[0]?.name).toMatch(/^tracelane-config-\d{4}-\d{2}-\d{2}\.json$/);
	expect(JSON.parse(saved[0]?.text ?? "{}")).toEqual(doc);
});

it("names the file by the UTC date, not the viewer's", () => {
	expect(exportFileName(new Date("2026-11-19T23:59:59Z"))).toBe(
		"tracelane-config-2026-11-19.json",
	);
	expect(exportFileName(new Date("2026-11-20T00:00:00Z"))).toBe(
		"tracelane-config-2026-11-20.json",
	);
});

it("config_dashboard_forbidden_hides_document: a 403 says who may export and saves nothing", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn(async () =>
			Response.json({ error: "role_forbidden" }, { status: 403 }),
		),
	);
	render(<ConfigExport />);
	press();
	expect(
		await screen.findByText("Only workspace admins can export configuration."),
	).toBeTruthy();
	expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
	expect(saved).toHaveLength(0);
});

it("an error shows an inline message with a retry that tries again", async () => {
	const f = vi
		.fn()
		.mockResolvedValueOnce(Response.json({ error: "x" }, { status: 503 }))
		.mockResolvedValueOnce(Response.json({ schema: "tracelane.config/v1" }));
	vi.stubGlobal("fetch", f);
	render(<ConfigExport />);
	press();
	expect(
		await screen.findByText(/The configuration could not be exported/),
	).toBeTruthy();
	expect(saved).toHaveLength(0);
	fireEvent.click(screen.getByRole("button", { name: "Retry" }));
	await waitFor(() => expect(saved).toHaveLength(1));
	expect(f).toHaveBeenCalledTimes(2);
	expect(screen.queryByText(/could not be exported/)).toBeNull();
});

it("a network failure is an error with a retry, not a crash", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn(async () => {
			throw new TypeError("offline");
		}),
	);
	render(<ConfigExport />);
	press();
	expect(await screen.findByRole("button", { name: "Retry" })).toBeTruthy();
});
