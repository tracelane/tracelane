/**
 * Pure URL-param transition for the traces filter bar. Extracted from FilterBar's
 * inline handler so the "a range PRESET clears a custom since/until window" rule
 * is unit-tested.
 *
 * The bug it fixes: the server builds the gateway window as
 * `since = sp.since ?? rangeSince(sp.range)` — a raw `?since=/&until=` (e.g. from
 * a dashboard chart-click) WINS over the preset. So if the URL still carries an
 * old custom window, clicking "1h" only set `range=1h` and the stale `since`
 * survived → the list showed rows OUTSIDE the picked range ("older entries beyond
 * 1h"). A preset and a custom window are mutually exclusive, so choosing a preset
 * must drop `since`/`until`.
 */

/** Params a range PRESET is mutually exclusive with — cleared when `range` is set. */
const CUSTOM_WINDOW_PARAMS = ["since", "until"] as const;

/**
 * Compute the next query string after setting `key=value` (empty `value`
 * deletes the key). Always resets `cursor` (any filter change re-paginates);
 * setting `range` also clears the custom `since`/`until` window.
 */
export function nextFilterParams(
	current: URLSearchParams,
	key: string,
	value: string,
): string {
	const next = new URLSearchParams(current.toString());
	if (value) next.set(key, value);
	else next.delete(key);
	next.delete("cursor"); // any filter change resets pagination
	if (key === "range") {
		for (const p of CUSTOM_WINDOW_PARAMS) next.delete(p);
	}
	return next.toString();
}
