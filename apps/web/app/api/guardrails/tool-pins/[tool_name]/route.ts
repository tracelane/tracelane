/**
 * DELETE /api/guardrails/tool-pins/[tool_name] — remove a tool's approved pin.
 *
 * GWY-15b: the gateway has mounted `DELETE /v1/guardrails/tool-pins/{tool_name}`
 * since tool pinning shipped (`tool_pins_api.rs:92`), and nothing in the dashboard
 * called it. Approving was one click; un-approving was not possible from the
 * product at all — a one-way door on the wedge's flagship surface. An owner who
 * approved the wrong definition, or who wanted a tool to stop being treated as
 * approved, had no path that did not involve us running SQL for them.
 *
 * Owner-gated at the gateway (`authenticate` → `can_admin`, one site covering all
 * four routes), so this proxy adds no authorization of its own — it forwards the
 * user's JWT and lets the gateway decide. What it must do is preserve the STATUS:
 * 403 (not an owner) and 404 (no such pin) mean different things to the person
 * clicking, and collapsing them into one "failed" message is the exact defect
 * recorded for the role-403 path.
 *
 * The tool name is taken from the URL path, never a body, and is re-encoded before
 * being forwarded so a name containing `/` or `?` cannot rewrite the upstream path.
 * The tenant is never in the URL — the gateway resolves it from the token.
 */

import { GatewayError, gatewayDelete } from "@/lib/gateway";
import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function DELETE(
	_req: Request,
	{ params }: { params: Promise<{ tool_name: string }> },
): Promise<NextResponse> {
	const { tool_name } = await params;

	if (typeof tool_name !== "string" || tool_name.length === 0) {
		return NextResponse.json(
			{ error: "tool_name is required" },
			{ status: 400 },
		);
	}

	// The gateway bounds the stored key at 256 bytes (MAX_TOOL_NAME_LEN); reject
	// here too rather than forwarding something that cannot match a stored pin.
	if (tool_name.length > 256) {
		return NextResponse.json({ error: "tool_name too long" }, { status: 400 });
	}

	try {
		await gatewayDelete(
			`/v1/guardrails/tool-pins/${encodeURIComponent(tool_name)}`,
		);
		return new NextResponse(null, { status: 204 });
	} catch (err) {
		if (err instanceof GatewayError) {
			if (err.status === 403) {
				return NextResponse.json(
					{ error: "role_forbidden", required_role: "owner" },
					{ status: 403 },
				);
			}
			if (err.status === 404) {
				return NextResponse.json({ error: "no_such_pin" }, { status: 404 });
			}
			return NextResponse.json(
				{ error: "upstream_error", status: err.status },
				{ status: err.status },
			);
		}
		return NextResponse.json({ error: "unexpected" }, { status: 500 });
	}
}
