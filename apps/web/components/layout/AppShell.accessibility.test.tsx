import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ pathname: "/dashboard" }));
vi.mock("next/navigation", () => ({ usePathname: () => state.pathname }));
vi.mock("@/components/NavProgress", () => ({
	NavProgressProvider: ({ children }: { children: ReactNode }) => children,
	TopLoadingBar: () => null,
}));
vi.mock("./Sidebar", () => ({ Sidebar: () => null }));
vi.mock("./TopBar", () => ({ TopBar: () => null }));
import { AppShell } from "./AppShell";

function markup(pathname: string) {
	state.pathname = pathname;
	return renderToStaticMarkup(
		<AppShell>
			<h1>Content</h1>
		</AppShell>,
	);
}

describe("workspace keyboard navigation", () => {
	it("provides a skip link whose target accepts focus", () => {
		const html = markup("/dashboard");
		expect(html).toContain('href="#workspace-content"');
		expect(html).toMatch(/<main[^>]*id="workspace-content"[^>]*tabindex="-1"/);
		expect(html.indexOf('href="#workspace-content"')).toBeLessThan(
			html.indexOf("<main"),
		);
	});
	it.each(["/onboarding", "/sign-in", "/auth/callback", "/s/public-token"])(
		"keeps the self-contained %s flow free of workspace chrome",
		(pathname) => {
			const html = markup(pathname);
			expect(html).not.toContain('href="#workspace-content"');
			expect(html.match(/<main/g)).toHaveLength(1);
			expect(html).toContain("Content");
		},
	);
});
