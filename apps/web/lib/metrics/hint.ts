/**
 * hintOf — the `?` affordance shows the plain-language hint AND, on the same
 * hover/focus, the source line (founder, 2026-09-04: "ensure every metric is
 * interactive and explanatory in the info ? button"). One place composes the
 * two registry fields into the one string every call site passes to
 * `StatCard`/`Kpi`'s `hint` prop, so the pairing can't drift per page.
 */
import type { MetricDef } from "./registry";

export function hintOf(
	m: Pick<MetricDef, "hint" | "source">,
): string | undefined {
	if (!m.hint) return undefined;
	return `${m.hint} Source: ${m.source}.`;
}
