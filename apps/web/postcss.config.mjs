/**
 * PostCSS config — registers the Tailwind v4 engine.
 *
 * Without this, `@import "tailwindcss"` in globals.css is inlined as static CSS
 * (theme variables + preflight) but the engine that scans markup and GENERATES
 * utility classes never runs, leaving `@tailwind utilities` unprocessed → the
 * whole app renders unstyled. See scripts/check-css-built.mjs (build guard).
 */

const config = {
	plugins: {
		"@tailwindcss/postcss": {},
	},
};

export default config;
