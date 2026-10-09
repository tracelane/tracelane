"use client";
/**
 * OG-60 slot page — a Gateway area the gateway may or may not serve (routing
 * `OG-11`/`OG-12`, cache `OG-51`, OTel export `OG-50`, guardrail policy `OG-30`). The tab
 * only exists when the gateway answers the area's read route. Cache and OTel export have
 * real editors (`CacheSettings`, `OtelExports`); routing and guardrail policy are
 * whole-document editors, so those pages show what the route answers, read-only and
 * secret-scrubbed, and say plainly that the editor is not built yet. It is not a mock:
 * every byte shown is the gateway's.
 */

import { CacheSettings } from "./CacheSettings";
import { OtelExports } from "./OtelExports";
import { Boundary, useControlQuery } from "./control";
import { EmptyNote, Panel } from "./fields";

const SECRET_KEY =
	/secret|token|authorization|password|api[-_]?key|credential|headers?$/i;

/** Hide any value whose key looks like a credential — a display must never echo one. */
export function scrub(v: unknown, depth = 0): unknown {
	if (depth > 8) return "…";
	if (Array.isArray(v)) return v.slice(0, 50).map((x) => scrub(x, depth + 1));
	if (v !== null && typeof v === "object") {
		return Object.fromEntries(
			Object.entries(v as Record<string, unknown>).map(([k, x]) => [
				k,
				SECRET_KEY.test(k) ? "[hidden]" : scrub(x, depth + 1),
			]),
		);
	}
	return v;
}

export function SlotView({
	slot,
}: {
	slot: { id: string; label: string; probe: string; spec: string };
}) {
	if (slot.id === "cache") return <CacheSettings />;
	if (slot.id === "otel") return <OtelExports />;
	return <ReadOnlySlot slot={slot} />;
}

function ReadOnlySlot({
	slot,
}: {
	slot: { id: string; label: string; probe: string; spec: string };
}) {
	const q = useControlQuery<unknown>(slot.probe);
	const absent = q.isError && q.error.status === 404;
	return (
		<Panel
			id={`slot-${slot.id}`}
			title={slot.label}
			description={`The dashboard editor for this area (${slot.spec}) is not built yet. Until then this page shows the live, read-only response of GET /v1/${slot.probe} when the gateway serves it; edit it through the API.`}
		>
			{absent ? (
				<EmptyNote>
					This gateway does not serve GET /v1/{slot.probe}, so there is nothing
					to show here yet. The tab appears in the Gateway strip only once it
					does.
				</EmptyNote>
			) : (
				<Boundary query={q} resource={slot.label} rows={3}>
					{(data) => (
						<pre
							className="max-h-[32rem] overflow-auto whitespace-pre-wrap break-all rounded-control bg-surface-2 p-3 font-mono text-xs"
							data-testid="slot-json"
						>
							{JSON.stringify(scrub(data), null, 2)}
						</pre>
					)}
				</Boundary>
			)}
		</Panel>
	);
}
