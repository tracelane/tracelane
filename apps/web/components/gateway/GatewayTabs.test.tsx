// @vitest-environment jsdom
// B-641: on a phone the Gateway tab strip squeezed its tabs into each other (flex items
// shrank below their text width), so the labels overlapped and could not be tapped.
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ push: vi.fn(), path: "/settings/gateway" }));
vi.mock("next/navigation", () => ({
	usePathname: () => h.path,
	useRouter: () => ({ push: h.push }),
}));
import { GatewayTabs } from "./GatewayTabs";
import { GATEWAY_TABS } from "./tabs-config";

afterEach(cleanup);
const slots = [
	{ id: "guardrail-integrations", label: "Guardrail integrations" },
];

it("tabs_never_shrink_below_their_label", () => {
	render(<GatewayTabs slots={slots} />);
	const links = screen
		.getByRole("navigation", { name: "Gateway settings" })
		.querySelectorAll("a");
	expect(links.length).toBe(GATEWAY_TABS.length + slots.length);
	for (const a of links) expect(a.className.split(/\s+/)).toContain("shrink-0");
});

it("phone_picker_lists_every_tab_and_navigates", () => {
	render(<GatewayTabs slots={slots} />);
	const picker = screen.getByLabelText(
		"Gateway settings section",
	) as HTMLSelectElement;
	expect(picker.options.length).toBe(GATEWAY_TABS.length + slots.length);
	expect(picker.value).toBe("/settings/gateway");
	fireEvent.change(picker, {
		target: { value: "/settings/gateway/guardrail-integrations" },
	});
	expect(h.push).toHaveBeenCalledWith(
		"/settings/gateway/guardrail-integrations",
	);
});

it("a_sub_route_keeps_its_own_tab_active", () => {
	h.path = "/settings/gateway/limits/workspace";
	render(<GatewayTabs slots={slots} />);
	const picker = screen.getByLabelText(
		"Gateway settings section",
	) as HTMLSelectElement;
	expect(picker.value).toBe("/settings/gateway/limits");
	const active = screen
		.getByRole("navigation", { name: "Gateway settings" })
		.querySelector('a[aria-current="page"]');
	expect(active?.getAttribute("href")).toBe("/settings/gateway/limits");
	h.path = "/settings/gateway";
});
