/**
 * DSH-01 — the in-app inbox. Thin proxy to the gateway.
 *
 * GET /api/notifications → { notifications, unread, cap }
 *
 * The gateway owns the store and the tenant resolution; this adds nothing but
 * transport. `unread` is counted server-side across ALL rows, not derived from
 * the capped page — a badge that counts only what fits on one page is a wrong
 * number on a trust surface.
 */

import { GatewayError, gatewayGet } from "@/lib/gateway";
import { NextResponse } from "next/server";

export type Notification = {
	id: string;
	kind: "quota" | "alert" | "promotion";
	title: string;
	body: string;
	severity: "info" | "warning" | "critical";
	/** Relative in-app path, or "" when not linkable. */
	link: string;
	read_at: string | null;
	created_at: string;
};

export type NotificationList = {
	notifications: Notification[];
	unread: number;
	cap: number;
};

export async function GET(): Promise<NextResponse> {
	try {
		return NextResponse.json(
			await gatewayGet<NotificationList>("/v1/notifications"),
		);
	} catch (err) {
		if (err instanceof GatewayError) {
			// Deliberately NOT an empty list. An inbox that cannot load and an
			// empty inbox look identical, and the bell must be able to say which
			// (spec: degraded-visible, never a silent empty).
			return NextResponse.json(
				{ error: "unavailable" },
				{ status: err.status >= 500 ? 502 : err.status },
			);
		}
		throw err;
	}
}
