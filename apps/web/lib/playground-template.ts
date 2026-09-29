/**
 * `EVL-03` §2 — the ONE `{{name}}` variable implementation, shared by the
 * playground route (renders before dispatch, §2 row 6) and the save-as-version
 * payload (`playground-prompt-version.ts`: `template_variables: variablesIn(system)`).
 * Syntax pinned by the spec table: `name` = `[A-Za-z_][A-Za-z0-9_]{0,127}` — the
 * same identifier shape `AuthorVersionForm.tsx:178` shows as a placeholder.
 *
 * Deliberately NOT the gateway's own renderer: `crates/gateway/src/prompt_routes.rs`
 * stores `template_variables` and never substitutes them (§3) — this file is the
 * dashboard-only preview/dispatch-time render, a separate, explicitly-scoped
 * implementation (spec §6: "Rendering `{{vars}}` inside the prompt router, evals
 * or the gateway" is out of scope).
 */

const VAR_TOKEN_RE = /\{\{([A-Za-z_][A-Za-z0-9_]{0,127})\}\}/g;

/** Every distinct `{{name}}` token in `text`, in first-seen order. A malformed
 * token (leading digit, hyphen, empty) is simply not a match — never an error,
 * since free text legitimately contains literal `{{…}}` outside this syntax. */
export function variablesIn(text: string): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (const m of text.matchAll(VAR_TOKEN_RE)) {
		const name = m[1];
		// The capture group always matches when the whole pattern does — this
		// guards `noUncheckedIndexedAccess`'s typing, not a real "no match" case.
		if (name === undefined) continue;
		if (!seen.has(name)) {
			seen.add(name);
			out.push(name);
		}
	}
	return out;
}

export interface RenderResult {
	rendered: string;
	/** Distinct unfilled variable names, in first-seen order. Empty means every
	 * variable in `text` had a value in `vars` — including an explicit `""`,
	 * which is a filled empty string, never "missing" (spec §5: the route's
	 * `400 unfilled_variable` fires only when a value was never supplied). */
	missing: string[];
}

/** Substitute every `{{name}}` token `vars` supplies a value for. An unfilled
 * token is left as the literal `{{name}}` (never silently dropped) and its
 * name is reported in `missing`, once per distinct name — the route refuses
 * the request when `missing` is non-empty, before any gateway call (§5). */
export function render(
	text: string,
	vars: Readonly<Record<string, string>>,
): RenderResult {
	const missingSeen = new Set<string>();
	const missing: string[] = [];
	const rendered = text.replace(VAR_TOKEN_RE, (token: string, name: string) => {
		if (Object.hasOwn(vars, name)) return vars[name] ?? "";
		if (!missingSeen.has(name)) {
			missingSeen.add(name);
			missing.push(name);
		}
		return token;
	});
	return { rendered, missing };
}
