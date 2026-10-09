/**
 * OG-60 slots: which of the not-yet-built Gateway areas (routing, cache, OTel export,
 * guardrail policy) the connected gateway actually answers. A slot is shown ONLY when its
 * read route answers — never a fake page for an API that is not there.
 */

import { gatewayResponse } from "@/lib/gateway";
import { GATEWAY_SLOTS, type GatewaySlot } from "@/lib/gateway-controls";

/** A route "answers" unless it is absent (404/405) or the gateway failed (5xx). */
export function slotAnswers(status: number): boolean {
	return status !== 404 && status !== 405 && status < 500;
}

function isRedirect(err: unknown): boolean {
	const digest = (err as { digest?: unknown } | null)?.digest;
	return typeof digest === "string" && digest.startsWith("NEXT_REDIRECT");
}

export async function detectSlots(): Promise<GatewaySlot[]> {
	const found = await Promise.all(
		GATEWAY_SLOTS.map(async (slot) => {
			try {
				const res = await gatewayResponse(`/v1/${slot.probe}`);
				await res.body?.cancel();
				return slotAnswers(res.status) ? slot : null;
			} catch (err) {
				// A NEXT_REDIRECT (no session) must propagate; anything else = not answering.
				if (isRedirect(err)) throw err;
				return null;
			}
		}),
	);
	return found.filter((s): s is GatewaySlot => s !== null);
}
