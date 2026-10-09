// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { TraceGroupTable } from "./TraceGroupTable";
afterEach(cleanup);

it("shows exact p50, p90, p95 and p99 from the group response", () => {
	render(
		<TraceGroupTable
			by="model"
			groups={[
				{
					group_key: "gpt-4o",
					trace_count: 10,
					error_traces: 1,
					avg_duration_us: 1200,
					p50_duration_us: 500,
					p90_duration_us: 900,
					p95_duration_us: 950,
					p99_duration_us: 990,
				},
			]}
		/>,
	);
	for (const label of ["p50", "p90", "p95", "p99"])
		expect(screen.getByRole("columnheader", { name: label })).toBeTruthy();
	for (const value of ["500µs", "900µs", "950µs", "990µs"])
		expect(screen.getByText(value)).toBeTruthy();
});

it("links every new label group to its trace filter and names empty groups", () => {
	for (const [by, param] of [
		["environment", "environment"],
		["release", "release"],
		["service", "service"],
		["user", "end_user"],
		["tag", "tag"],
	] as const) {
		const { unmount } = render(
			<TraceGroupTable
				by={by}
				groups={[
					{
						group_key: "prod us",
						trace_count: 2,
						error_traces: 0,
						avg_duration_us: 1,
						p50_duration_us: 1,
						p90_duration_us: 1,
						p95_duration_us: 1,
						p99_duration_us: 1,
					},
				]}
			/>,
		);
		expect(
			screen.getByRole("link", { name: "prod us" }).getAttribute("href"),
		).toBe(`/traces?${param}=prod%20us`);
		unmount();
	}
	render(
		<TraceGroupTable
			by="tag"
			groups={[
				{
					group_key: "",
					trace_count: 1,
					error_traces: 0,
					avg_duration_us: 1,
					p50_duration_us: 1,
					p90_duration_us: 1,
					p95_duration_us: 1,
					p99_duration_us: 1,
				},
			]}
		/>,
	);
	expect(screen.getByText("(not set)")).toBeTruthy();
});
