// @vitest-environment jsdom
/**
 * OG-51 cache and OG-50 OTel export editors (the slot pages with real writes). Each write is
 * asserted on the request the gateway would receive, and a refusal on the wording shown —
 * never on "it rendered".
 */
import {
	cleanup,
	fireEvent,
	screen,
	waitFor,
	within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CacheSettings, type CacheView } from "./CacheSettings";
import { OtelExports, parseHeaderLines } from "./OtelExports";
import { SlotView } from "./SlotView";
import { json, mockFetch, mount, openDialog, when } from "./test-utils";

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

const cacheView = (over: Partial<CacheView["settings"]> = {}): CacheView => ({
	plan: { cache_control: true, ttl_hours: 24 },
	settings: {
		mode: { value: "inherit", source: "default" },
		ttl_hours: { value: null, source: "default" },
		namespace_by: { value: "workspace", source: "default" },
		semantic: { value: true, source: "default" },
		updated_at: null,
		...over,
	},
	effective: {
		enabled: true,
		why_off: null,
		ttl_hours: 24,
		ttl_source: "plan",
		ttl_ceiling_hours: 720,
	},
	epochs: [{ scope: "workspace", epoch: 2 }],
	stats: {
		window_hours: 24,
		hits: 9,
		cost_saved_usd: 0.5,
		stats_unavailable: false,
	},
});

describe("slot routing", () => {
	it("cache and otel mount their editors; routing keeps the read-only slot", async () => {
		mockFetch(when("GET", "/cache", () => json(cacheView())));
		mount(
			<SlotView
				slot={{ id: "cache", label: "Cache", probe: "cache", spec: "OG-51" }}
			/>,
		);
		expect(await screen.findByTestId("cache-effective")).toBeTruthy();
		expect(screen.queryByTestId("slot-json")).toBeNull();
	});
});

describe("Cache editor", () => {
	it("saves the full document the gateway's PUT takes, then says what changed", async () => {
		const { calls } = mockFetch(
			when("GET", "/cache", () => json(cacheView())),
			when("PUT", "/cache/settings", () => json({ changed: true })),
		);
		mount(<CacheSettings />);
		await screen.findByTestId("cache-effective");
		fireEvent.change(screen.getByLabelText(/Response cache/), {
			target: { value: "on" },
		});
		fireEvent.change(screen.getByLabelText(/TTL \(hours\)/), {
			target: { value: "12" },
		});
		fireEvent.change(screen.getByLabelText(/Cache namespace/), {
			target: { value: "project" },
		});
		fireEvent.click(screen.getByLabelText(/Serve a near-identical/));
		fireEvent.click(
			screen.getByRole("button", { name: "Save cache settings" }),
		);
		await screen.findByText("Saved");
		const put = calls.find((c) => c.method === "PUT");
		expect(put?.url).toContain("/cache/settings");
		expect(put?.body).toEqual({
			mode: "on",
			ttl_hours: 12,
			namespace_by: "project",
			semantic: false,
		});
	});

	it("shows the gateway's plan refusal and does not claim success", async () => {
		mockFetch(
			when("GET", "/cache", () => json(cacheView())),
			when("PUT", "/cache/settings", () =>
				json(
					{
						error: "cache_control_not_entitled",
						message: "turning the response cache on is not part of this plan",
					},
					403,
				),
			),
		);
		mount(<CacheSettings />);
		await screen.findByTestId("cache-effective");
		fireEvent.change(screen.getByLabelText(/Response cache/), {
			target: { value: "on" },
		});
		fireEvent.click(
			screen.getByRole("button", { name: "Save cache settings" }),
		);
		expect(await screen.findByRole("alert")).toBeTruthy();
		expect(screen.queryByText("Saved")).toBeNull();
	});

	it("a bad TTL is refused in the form before any request", async () => {
		const { calls } = mockFetch(when("GET", "/cache", () => json(cacheView())));
		mount(<CacheSettings />);
		await screen.findByTestId("cache-effective");
		fireEvent.change(screen.getByLabelText(/TTL \(hours\)/), {
			target: { value: "0" },
		});
		const save = screen.getByRole("button", {
			name: "Save cache settings",
		}) as HTMLButtonElement;
		expect(save.disabled).toBe(true);
		expect(calls.some((c) => c.method === "PUT")).toBe(false);
	});

	it("a viewer sees the controls disabled with the reason, and can write nothing", async () => {
		mockFetch(when("GET", "/cache", () => json(cacheView())));
		mount(<CacheSettings />, "viewer");
		await screen.findByTestId("cache-effective");
		expect(
			(
				screen.getByRole("button", {
					name: "Save cache settings",
				}) as HTMLButtonElement
			).disabled,
		).toBe(true);
		expect(screen.getAllByTestId("why-disabled").length).toBeGreaterThan(0);
	});

	it("invalidate posts the scope and never says the rows were erased", async () => {
		const { calls } = mockFetch(
			when("GET", "/cache", () => json(cacheView())),
			when("POST", "/cache/invalidate", () =>
				json({
					scope: "model:gpt-4o",
					epoch: 3,
					effect: "stop_serving",
					note: "cached answers for this scope are no longer served; stored rows age out by TTL",
				}),
			),
		);
		mount(<CacheSettings />);
		await screen.findByTestId("cache-effective");
		fireEvent.change(screen.getByLabelText(/^Scope/), {
			target: { value: "model:gpt-4o" },
		});
		fireEvent.click(
			screen.getByRole("button", { name: "Stop serving this scope" }),
		);
		const out = await screen.findByText(/generation 3/);
		expect(out.textContent).toMatch(/age out by TTL/);
		expect(out.textContent).not.toMatch(/erased|deleted/i);
		expect(calls.find((c) => c.method === "POST")?.body).toEqual({
			scope: "model:gpt-4o",
		});
	});

	it("off for a stated reason is said, with the reason", async () => {
		const v = cacheView();
		v.effective = {
			...v.effective,
			enabled: false,
			why_off: "content_capture_off",
		};
		mockFetch(when("GET", "/cache", () => json(v)));
		mount(<CacheSettings />);
		expect((await screen.findByTestId("cache-effective")).textContent).toMatch(
			/^Off — Content capture is off/,
		);
	});
});

const exportRow = (over: Record<string, unknown> = {}) => ({
	id: "e1",
	name: "prod collector",
	url: "https://collector.example.com/v1/traces",
	header_names: ["authorization"],
	enabled: true,
	include_content: false,
	sample_ratio: 1,
	only_errors: false,
	status: "ok",
	last_success_at: "2026-10-05T08:00:00Z",
	last_error_class: null,
	delivered: 10,
	dropped: 1,
	failed: 2,
	...over,
});
const list = (exports: unknown[], enabled = true) => ({
	exports,
	plan: { export_enabled: enabled, max_exports: 3 },
});

describe("parseHeaderLines", () => {
	it("splits on the first colon and refuses a line without one", () => {
		expect(parseHeaderLines("Authorization: Bearer a:b\n\nX-Org: 1")).toEqual({
			headers: { Authorization: "Bearer a:b", "X-Org": "1" },
		});
		expect("error" in parseHeaderLines("no colon here")).toBe(true);
		expect("error" in parseHeaderLines(": value")).toBe(true);
	});
});

describe("OTel export editor", () => {
	it("lists exports with header NAMES and never a value", async () => {
		mockFetch(when("GET", "/exports/otel", () => json(list([exportRow()]))));
		mount(<OtelExports />);
		expect(await screen.findByText("prod collector")).toBeTruthy();
		expect(screen.getByText(/headers: authorization/)).toBeTruthy();
		expect(document.body.textContent).not.toMatch(/Bearer/);
	});

	it("creates an export: headers become a map, the body carries no tenant", async () => {
		const { calls } = mockFetch(
			when("GET", "/exports/otel", () => json(list([]))),
			when("POST", "/exports/otel", () => json(exportRow())),
		);
		mount(<OtelExports />);
		await screen.findByText(/No exports/);
		fireEvent.change(screen.getByLabelText("Name"), {
			target: { value: "grafana" },
		});
		fireEvent.change(screen.getByLabelText(/OTLP\/HTTP traces URL/), {
			target: { value: "https://otlp.example.com/v1/traces" },
		});
		fireEvent.change(screen.getByLabelText(/^Headers/), {
			target: { value: "Authorization: Basic abc" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Add export" }));
		await waitFor(() =>
			expect(calls.some((c) => c.method === "POST")).toBe(true),
		);
		expect(calls.find((c) => c.method === "POST")?.body).toEqual({
			name: "grafana",
			url: "https://otlp.example.com/v1/traces",
			headers: { Authorization: "Basic abc" },
			include_content: false,
			only_errors: false,
			sample_ratio: 1,
		});
	});

	it("names the field the gateway refused", async () => {
		mockFetch(
			when("GET", "/exports/otel", () => json(list([]))),
			when("POST", "/exports/otel", () =>
				json(
					{
						error: "invalid_field",
						message: "url must be https",
						field: "url",
					},
					400,
				),
			),
		);
		mount(<OtelExports />);
		await screen.findByText(/No exports/);
		fireEvent.change(screen.getByLabelText("Name"), { target: { value: "x" } });
		fireEvent.change(screen.getByLabelText(/OTLP\/HTTP traces URL/), {
			target: { value: "http://insecure.example.com" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Add export" }));
		expect(await screen.findByText("url must be https")).toBeTruthy();
	});

	it("says plainly when the plan does not include export", async () => {
		mockFetch(when("GET", "/exports/otel", () => json(list([], false))));
		mount(<OtelExports />);
		expect(
			await screen.findByText(/not part of this workspace’s plan/),
		).toBeTruthy();
	});

	it("disable PATCHes enabled=false; test reports the class and latency; delete asks first", async () => {
		const { calls } = mockFetch(
			when("GET", "/exports/otel", () => json(list([exportRow()]))),
			when("PATCH", "/exports/otel/e1", () =>
				json(exportRow({ enabled: false })),
			),
			when("POST", "/exports/otel/e1/test", () =>
				json({ ok: false, class: "http_401", latency_ms: 31 }),
			),
			when(
				"DELETE",
				"/exports/otel/e1",
				() => new Response(null, { status: 204 }),
			),
		);
		mount(<OtelExports />);
		await screen.findByText("prod collector");
		fireEvent.click(
			screen.getByRole("button", { name: "Disable prod collector" }),
		);
		await waitFor(() =>
			expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({
				enabled: false,
			}),
		);
		fireEvent.click(
			screen.getByRole("button", {
				name: "Send a test span to prod collector",
			}),
		);
		expect(await screen.findByText(/Refused \(http_401, 31 ms\)/)).toBeTruthy();
		fireEvent.click(
			screen.getByRole("button", { name: "Delete prod collector" }),
		);
		expect(calls.some((c) => c.method === "DELETE")).toBe(false);
		fireEvent.click(
			within(openDialog()).getByRole("button", { name: "Delete export" }),
		);
		await waitFor(() =>
			expect(calls.some((c) => c.method === "DELETE")).toBe(true),
		);
	});
});
