/**
 * OBS-18 server half — resolves the existing verdict and the caller's role,
 * then hands both to the client control.
 *
 * Split from `TraceFlag` because the role must be read SERVER-side: a client
 * that decides its own permissions is decoration. The gateway enforces the same
 * rule regardless (`may_write` in `annotation_routes.rs`), so this only makes
 * the UI honest about what will happen — it is not the control.
 */

import { requireSession } from "@/lib/auth";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { type Annotation, TraceFlag } from "./TraceFlag";

export async function TraceFlagPanel({ traceId }: { traceId: string }) {
	const session = await requireSession();
	// A viewer may READ verdicts and may not write them (IDENTITY_TEAM_SPEC §1).
	const canWrite = session.role !== "viewer";

	let mine: Annotation | null = null;
	try {
		const all = await gatewayGet<Annotation[]>(
			`/v1/traces/${encodeURIComponent(traceId)}/annotations`,
		);
		// Trace-level verdict authored by THIS user. Span-level flags belong to
		// the span inspector, not the header.
		mine =
			all.find((a) => a.span_id === "" && a.author_sub === session.userId) ??
			null;
	} catch (err) {
		// Degraded-visible, not silent: if the read fails we still render the
		// control unflagged rather than hiding the feature. Hiding it would look
		// identical to "this trace has no flag", which is the §18 shape.
		if (!(err instanceof GatewayError)) throw err;
		mine = null;
	}

	return <TraceFlag traceId={traceId} initial={mine} canWrite={canWrite} />;
}
