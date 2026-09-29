import { sections } from "@/components/layout/nav-config";
/**
 * OBS-02 §7 rows 1–3. Pure rules, so each is a plain assertion.
 */
import { describe, expect, it } from "vitest";
import {
	MIN_SEARCH_CHARS,
	asTraceId,
	buildCommands,
	destinations,
} from "./commands";

describe("coverage", () => {
	it("every sidebar destination is a palette destination — one list, never a copy", () => {
		const palette = new Set(buildCommands("").map((c) => c.href));
		const sidebar = sections.flatMap((s) => s.items.map((i) => i.href));
		expect(sidebar.length).toBeGreaterThan(20);
		for (const href of sidebar) expect(palette.has(href), href).toBe(true);
		expect(destinations()).toHaveLength(sidebar.length);
	});

	it("verbs come first on an empty query and every verb lands on a real destination", () => {
		const all = buildCommands("");
		expect(all[0]?.group).toBe("action");
		const known = new Set([
			...sections.flatMap((s) => s.items.map((i) => i.href)),
			"/traces/compare",
			"/dashboards/new",
		]);
		for (const c of all.filter((c) => c.group === "action")) {
			expect(known.has(c.href), c.href).toBe(true);
		}
	});
});

describe("trace ids", () => {
	it("a dashed UUID opens that trace, first", () => {
		const id = "3f2a9c1e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
		const [first] = buildCommands(id);
		expect(first?.href).toBe(`/traces/${id}`);
	});

	it("a 32-hex W3C id is normalised losslessly to the dashed form", () => {
		expect(asTraceId("3F2A9C1E1B2C4D5E8F90A1B2C3D4E5F6")).toBe(
			"3f2a9c1e-1b2c-4d5e-8f90-a1b2c3d4e5f6",
		);
	});

	it("text that is not an id is never offered as a trace", () => {
		for (const q of ["not-a-uuid", "3f2a9c1e", "g".repeat(32)]) {
			expect(asTraceId(q)).toBeNull();
			expect(buildCommands(q).some((c) => c.id === "query-trace")).toBe(false);
		}
	});
});

describe("search and model filter", () => {
	it("any text offers a model filter; the search needs OBS-01's minimum", () => {
		const cmds = buildCommands("gpt-4o");
		expect(cmds.find((c) => c.id === "query-model")?.href).toBe(
			"/traces?model=gpt-4o",
		);
		expect(cmds.find((c) => c.id === "query-search")?.href).toBe(
			"/traces?q=gpt-4o",
		);
		const short = "abc";
		expect(short.length).toBeLessThan(MIN_SEARCH_CHARS);
		expect(buildCommands(short).some((c) => c.id === "query-search")).toBe(
			false,
		);
	});

	it("a query that names a command lists it before the fallbacks", () => {
		const cmds = buildCommands("alias");
		expect(cmds[0]?.id).toBe("verb-alias");
	});

	it("user text is URL-encoded, never spliced raw into a route", () => {
		const cmds = buildCommands("a&b=c/d");
		expect(cmds.find((c) => c.id === "query-model")?.href).toBe(
			"/traces?model=a%26b%3Dc%2Fd",
		);
	});
});

describe("current object verbs", () => {
	const context = [
		{
			id: "trace-dataset",
			label: "Add this trace to dataset",
			href: "",
			target: true,
			group: "action" as const,
		},
		{
			id: "trace-session",
			label: "Open session",
			href: "/sessions/s%2F1",
			group: "action" as const,
		},
	];
	it("puts the mounted object before generic navigation", () => {
		expect(buildCommands("", context).slice(0, 2)).toEqual(context);
	});
	it("filters contextual commands using the same query", () => {
		expect(
			buildCommands("session", context).some((c) => c.id === "trace-session"),
		).toBe(true);
		expect(
			buildCommands("session", context).some((c) => c.id === "trace-dataset"),
		).toBe(false);
	});
	it("does not invent object actions without a mounted context", () => {
		expect(buildCommands("").some((c) => c.id.startsWith("trace-"))).toBe(
			false,
		);
	});
	it("retains navigation and dialog descriptors without executing anything", () => {
		expect(buildCommands("", context)[0]).toMatchObject({
			target: true,
			href: "",
		});
		expect(buildCommands("", context)[1]?.href).toBe("/sessions/s%2F1");
	});
});
