import type { WorkspaceGlanceResponse } from "@/lib/metrics/fetch";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { WorkspaceGlance } from "./WorkspaceGlance";

const glance: WorkspaceGlanceResponse = {
	as_of: "2026-10-01T12:00:00Z",
	cache_ttl_seconds: 300,
	deployment: "hosted",
	volume: { state: "ok", window_days: 30, traces: 200, spans: 600 },
	ingest: {
		state: "ok",
		source: "meter",
		total_bytes: 10_000_000,
		since: "2026-09-13",
		period_bytes: 2_000_000,
		period_start: "2026-10-01",
		period_kind: "calendar_month",
	},
	stored: {
		state: "unavailable",
		kind: "hot_resident_gauge",
		bytes: null,
		as_of: null,
	},
	agents: { state: "ok", window_days: 7, active: 4, direct_calls: 20 },
	spend: {
		state: "ok",
		period_start: "2026-10-01",
		period_kind: "calendar_month",
		usd: 12.34,
		unpriced_requests: 2,
	},
	providers: {
		state: "ok",
		window_days: 7,
		count: 3,
		top: ["openai", "anthropic", "gemini"],
	},
	storage: null,
};

it("labels each window and leaves an unavailable stored gauge unknown", () => {
	const html = renderToStaticMarkup(<WorkspaceGlance data={glance} />);
	expect(html).toContain("Traces · last 30 days");
	expect(html).toContain("Spend this billing period");
	expect(html).toContain("not computed yet");
	expect(html).toContain("Not affected by the time range");
	expect(html).toContain("2 calls unpriced");
	expect(html).toContain("On-disk size isn&#x27;t shown");
	expect(html).not.toContain("Storage on this server");
});

it("keeps sections independent when one exceeds its read cap", () => {
	const html = renderToStaticMarkup(
		<WorkspaceGlance
			data={{
				...glance,
				volume: {
					...glance.volume,
					state: "over_cap",
					traces: null,
					spans: null,
				},
			}}
		/>,
	);
	expect(html).toContain("This window is too large to count on demand");
	expect(html).toContain("$12.34");
});

it("shows onboarding instead of measured zeros before the first request", () => {
	const html = renderToStaticMarkup(
		<WorkspaceGlance
			data={{
				...glance,
				volume: { state: "ok", window_days: 30, traces: 0, spans: 0 },
				ingest: { ...glance.ingest, state: "ok", total_bytes: 0 },
			}}
		/>,
	);
	expect(html).toContain("Nothing recorded yet");
	expect(html).not.toContain("0 spans per trace");
});

it("does not label retained self-host spans as lifetime or billing-period ingest", () => {
	const html = renderToStaticMarkup(
		<WorkspaceGlance
			data={{
				...glance,
				deployment: "self_host",
				ingest: {
					...glance.ingest,
					source: "spans",
					period_bytes: null,
					period_kind: null,
				},
				stored: {
					...glance.stored,
					state: "ok",
					kind: "span_bytes_sum",
					bytes: 42,
				},
			}}
		/>,
	);
	expect(html).toContain("Stored (logical, within retention)");
	expect(html).not.toContain("Ingested since metering began");
	expect(html).not.toContain("Ingested this billing period");
});
