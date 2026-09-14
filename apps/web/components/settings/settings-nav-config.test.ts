/**
 * `SET-36` §7 proofs 1, 2 and 4 — the ONE settings list, held to the filesystem.
 *
 * Proof 1 is fs-driven on purpose: a test that pins "ten items" would have to be
 * edited every time a settings page ships, and the edit is exactly the step that
 * gets skipped. Walking `app/settings/*\/page.tsx` means a new page that is not
 * placed in a group turns this red the day it lands — the `/settings/evals` shape
 * (in the tree, in `SettingsNav`, never in the chrome sweep) cannot recur.
 */

import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import {
	ALL_CHROME_ROUTES,
	SETTINGS_HREF,
} from "@/components/layout/nav-model";
import { describe, expect, it } from "vitest";
import {
	SETTINGS_GROUPS,
	SETTINGS_ITEMS,
	activeSettingsHref,
} from "./settings-nav-config";

const SETTINGS_APP_DIR = join(__dirname, "..", "..", "app", "settings");

/** Every `app/settings/<dir>/page.tsx` as a route — the pages that actually exist. */
function settingsRoutesOnDisk(): string[] {
	return readdirSync(SETTINGS_APP_DIR)
		.filter((name) => {
			const full = join(SETTINGS_APP_DIR, name);
			return (
				statSync(full).isDirectory() &&
				readdirSync(full).includes("page.tsx") &&
				!name.startsWith("[")
			);
		})
		.map((name) => `/settings/${name}`)
		.sort();
}

describe("SET-36 — one settings list, held to the tree", () => {
	it("places every settings page on disk in EXACTLY one group (proof 1)", () => {
		const onDisk = settingsRoutesOnDisk();
		const inConfig = SETTINGS_ITEMS.map((i) => i.href);
		expect(
			onDisk.length,
			"no settings pages found — wrong dir?",
		).toBeGreaterThan(0);
		// Present exactly once: a stranded page and a duplicate are both red.
		expect([...inConfig].sort()).toEqual(onDisk);
		expect(new Set(inConfig).size).toBe(inConfig.length);
	});

	it("is swept by the dead-button walk — /settings/evals included (proof 2)", () => {
		for (const { href } of SETTINGS_ITEMS) {
			expect(ALL_CHROME_ROUTES, `${href} not in ALL_CHROME_ROUTES`).toContain(
				href,
			);
		}
		// The specific gap this closes: before SET-36, nav-config's own copy of the
		// settings list had never learned about Online Evals.
		expect(ALL_CHROME_ROUTES).toContain("/settings/evals");
		expect(ALL_CHROME_ROUTES).toContain("/settings/account");
	});

	it("keeps the /settings redirect and the rail in agreement (proof 4)", () => {
		expect(SETTINGS_HREF).toBe(SETTINGS_ITEMS[0]?.href);
	});

	it("is four named groups, each non-empty, labels unique (spec §5)", () => {
		expect(SETTINGS_GROUPS.length).toBeLessThanOrEqual(4);
		for (const g of SETTINGS_GROUPS) {
			expect(g.items.length, `group "${g.label}" is empty`).toBeGreaterThan(0);
		}
		const labels = SETTINGS_GROUPS.map((g) => g.label);
		expect(new Set(labels).size).toBe(labels.length);
	});

	it("resolves the active page by LONGEST prefix, and null outside settings", () => {
		expect(activeSettingsHref("/settings/api-keys")).toBe("/settings/api-keys");
		expect(activeSettingsHref("/settings/api-keys/new")).toBe(
			"/settings/api-keys",
		);
		// A bare prefix of another route must not match it.
		expect(activeSettingsHref("/settings/api-keys-archive")).toBeNull();
		expect(activeSettingsHref("/settings")).toBeNull();
		expect(activeSettingsHref("/dashboard")).toBeNull();
	});
});
