// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
const route = vi.hoisted(() => ({ pathname: "/traces/example" }));
vi.mock("next/navigation", () => ({ usePathname: () => route.pathname }));
vi.mock("./AccountMenu", () => ({ AccountMenu: () => null }));
import { Sidebar } from "./Sidebar";
afterEach(() => {
	cleanup();
	document.cookie = "sidebar_state=;max-age=0;path=/";
	route.pathname = "/traces/example";
});
it("collapses on entering trace detail without a pinned preference", () => {
	const { rerender } = render(<Sidebar defaultCollapsed={false} />);
	expect(screen.getByRole("button", { name: "Expand sidebar" })).toBeTruthy();
	fireEvent.click(screen.getByRole("button", { name: "Expand sidebar" }));
	rerender(<Sidebar defaultCollapsed={false} />);
	expect(screen.getByRole("button", { name: "Collapse sidebar" })).toBeTruthy();
	route.pathname = "/traces/next";
	rerender(<Sidebar defaultCollapsed={false} />);
	expect(screen.getByRole("button", { name: "Collapse sidebar" })).toBeTruthy();
});
it("respects an explicitly expanded cookie on trace entry", () => {
	document.cookie = "sidebar_state=expanded;path=/";
	render(<Sidebar defaultCollapsed={false} />);
	expect(screen.getByRole("button", { name: "Collapse sidebar" })).toBeTruthy();
});
it("keeps list routes expanded", () => {
	route.pathname = "/traces";
	render(<Sidebar defaultCollapsed={false} />);
	expect(screen.getByRole("button", { name: "Collapse sidebar" })).toBeTruthy();
});
