"use client";

import { useEffect, useState } from "react";

export type Theme = "dark" | "light";

const COOKIE = "theme";
const ONE_YEAR = 60 * 60 * 24 * 365;

// Inline SVG — matches the Sidebar's no-icon-dependency convention (h-4 w-4).
function SunIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={2}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<circle cx="12" cy="12" r="4" />
			<path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
		</svg>
	);
}

function MoonIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={2}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
		</svg>
	);
}

/**
 * Theme toggle (ADR-053). Flips `data-theme` on `<html>` and persists the
 * choice to a `theme` cookie so the no-flash inline script in `app/layout.tsx`
 * applies the right token set on the next load's first frame — no flash of the
 * wrong theme. Light is the default.
 *
 * Initial state is hardcoded "light" (matching the server render, so hydration
 * is clean) then synced once on mount from the `data-theme` the inline script
 * set — a one-frame label correction, never a hydration mismatch.
 */
export function ThemeToggle({ compact = false }: { compact?: boolean } = {}) {
	const [theme, setTheme] = useState<Theme>("light");

	useEffect(() => {
		const seeded = document.documentElement.dataset.theme;
		if (seeded === "light" || seeded === "dark") setTheme(seeded);
	}, []);

	function toggle() {
		const next: Theme = theme === "dark" ? "light" : "dark";
		setTheme(next);
		document.documentElement.dataset.theme = next;
		// Lax so it rides top-level navigations; ~1yr persistence.
		document.cookie = `${COOKIE}=${next}; path=/; max-age=${ONE_YEAR}; samesite=lax`;
	}

	const nextLabel = theme === "dark" ? "light" : "dark";

	// Compact icon-only affordance for the top bar — a monochrome glyph on a
	// `--surface-2` container chip, which is the shape the P0 brief specifies for
	// every icon in the app. `--surface-3` is the hover step, matching the
	// well -> press-step pair the nav rail uses, so the whole chrome answers a
	// pointer the same way. `rounded-full` is deliberate here and shared with the
	// workspace pill beside it: these are chips, not controls with a field.
	if (compact) {
		return (
			<button
				type="button"
				onClick={toggle}
				aria-label={`Switch to ${nextLabel} theme`}
				className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-surface-2 text-ink transition-colors hover:bg-surface-3 hover:text-ink"
			>
				{theme === "dark" ? <SunIcon /> : <MoonIcon />}
			</button>
		);
	}

	// The full-width row variant. NOTE: it has no call site in `apps/web` today —
	// `TopBar` is the only consumer and it always passes `compact`. Left in place
	// (deleting an exported variant is not this pass's business) but brought onto
	// the same tokens: the hover was `--surface-2` at 50% opacity, an opacity-faded
	// token that resolves to a value the palette does not contain, and the radius
	// was a third value. Now: the control radius, and the same well hover step the
	// chip and the rail use.
	return (
		<button
			type="button"
			onClick={toggle}
			aria-label={`Switch to ${nextLabel} theme`}
			className="flex w-full items-center gap-3 rounded-[var(--radius-control)] px-3 py-2 text-sm text-ink-2 transition-colors hover:bg-surface-2 hover:text-ink"
		>
			{theme === "dark" ? <SunIcon /> : <MoonIcon />}
			<span>{theme === "dark" ? "Light mode" : "Dark mode"}</span>
		</button>
	);
}
