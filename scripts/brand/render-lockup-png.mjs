#!/usr/bin/env node
/**
 * Rasterise the brand lockup — the ONE thing `build-brand-assets.py` cannot draw.
 *
 * That script is stdlib-only by design and has no font rasteriser; the lockup carries
 * the Inter wordmark as `<text>`, deliberately (outlining it would fork the letterforms
 * from the product font). So this script takes the SVG masters that script writes,
 * embeds the site's own `inter-var-latin.woff2`, and screenshots them in Chromium.
 * Derived from the masters, never a second source: change the mark in the Python
 * geometry, re-run that, then re-run this.
 *
 * Emits:
 *   brand/png/tracelane-lockup-horizontal-black.png   4000×800, transparent — decks on light
 *   brand/png/tracelane-lockup-horizontal-white.png   4000×800, transparent — decks on dark
 *   apps/site/public/og-default.png                   1200×630 — the link-preview card
 *
 * WHY THE OG CARD IS HERE. The previous `og-default.png` (dated 2026-08-10) carried the
 * retired positioning — "predictive reliability for ai agents", "v1 ships tue jun 16,
 * 2026" — and no mark at all, and it was what every shared link showed for a month
 * after ADR-055 fixed the lead. A hand-made card rots exactly like a hand-made icon;
 * this one is rendered from the same masters and the site's own <title> string.
 *
 * Playwright is reached through `apps/web` (its `@playwright/test` dependency) — nothing
 * new is installed for this.
 *
 *   node scripts/brand/render-lockup-png.mjs
 */
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const require = createRequire(resolve(ROOT, "apps/web/package.json"));
const { chromium } = require("@playwright/test");

const font = readFileSync(
	resolve(ROOT, "apps/site/public/fonts/inter-var-latin.woff2"),
).toString("base64");
const svg = (name) => readFileSync(resolve(ROOT, "brand/svg", name), "utf8");

// Base.astro's default <title>, minus the wordmark the lockup already carries.
const TAGLINE = "the flight recorder for AI agents";

const CSS = `@font-face{font-family:Inter;src:url(data:font/woff2;base64,${font}) format("woff2");font-weight:100 900}
html,body{margin:0;background:transparent}`;

const jobs = [
	{
		out: "brand/png/tracelane-lockup-horizontal-black.png",
		html: svg("tracelane-lockup-horizontal-black.svg"),
		w: 500,
		h: 100,
		scale: 8,
		transparent: true,
	},
	{
		out: "brand/png/tracelane-lockup-horizontal-white.png",
		html: svg("tracelane-lockup-horizontal-white.svg"),
		w: 500,
		h: 100,
		scale: 8,
		transparent: true,
	},
	{
		out: "apps/site/public/og-default.png",
		html: `<div style="width:1200px;height:630px;background:#0D0D0D;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:40px;font-family:Inter,sans-serif">
			<div style="width:640px">${svg("tracelane-lockup-horizontal-white.svg").replace('width="500" height="100"', 'width="640" height="128"')}</div>
			<div style="color:#A3A3A3;font-size:34px;font-weight:500;letter-spacing:-0.01em">${TAGLINE}</div>
		</div>`,
		w: 1200,
		h: 630,
		scale: 1,
		transparent: false,
	},
];

const browser = await chromium.launch();
for (const j of jobs) {
	const page = await browser.newPage({
		viewport: { width: j.w, height: j.h },
		deviceScaleFactor: j.scale,
	});
	await page.setContent(
		`<!doctype html><style>${CSS} svg{display:block}</style>${j.html}`,
	);
	await page.evaluate(() => document.fonts.ready);
	const buf = await page.screenshot({
		omitBackground: j.transparent,
		type: "png",
	});
	writeFileSync(resolve(ROOT, j.out), buf);
	console.log(
		`${j.out}  ${j.w * j.scale}x${j.h * j.scale}  ${buf.length} bytes`,
	);
	await page.close();
}
await browser.close();
