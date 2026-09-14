/**
 * GET  /api/dashboards   — list dashboards for the authenticated tenant.
 * POST /api/dashboards   — create a new dashboard (editor role or above).
 *
 * tenant_id comes from the WorkOS session → internal UUID via upsertTenantId.
 * The raw WorkOS org id (session.tenantId) NEVER touches the dashboards table
 * directly — the internal UUID is the only binding (CLAUDE.md §3, tenancy trap).
 *
 * Write gate: `member` role or above (not `viewer`). The gateway owns the
 * prompt-authoring role gate on crates/gateway/src/prompt_routes.rs — that maps
 * `can_write_prompt` to Member/Owner. We mirror that here: viewer = read-only,
 * member/owner/admin = can edit.
 */

import { db } from "@/db";
import { dashboards } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { upsertTenantId } from "@/lib/tenant";
import { count, desc, eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

/** Viewer-only guard: viewers may not write. */
function canEdit(role: string | null | undefined): boolean {
	// Allowlist (not denylist) — an unrecognised slug defaults to no write access.
	return role === "owner" || role === "admin" || role === "member";
}

const MAX_DASHBOARDS = 50;
const MAX_TITLE_LEN = 60;

export async function GET(): Promise<NextResponse> {
	const session = await requireSession();
	const tenantDbId = await upsertTenantId(session.tenantId);

	const rows = await db
		.select({
			id: dashboards.id,
			name: dashboards.name,
			createdBy: dashboards.createdBy,
			createdAt: dashboards.createdAt,
			updatedAt: dashboards.updatedAt,
		})
		.from(dashboards)
		.where(eq(dashboards.tenantId, tenantDbId))
		.orderBy(desc(dashboards.updatedAt));

	// Attach tile count per dashboard (a separate aggregate query avoids a JOIN
	// that would need groupBy on every column, and the list is at most 50 rows).
	const { dashboardTiles } = await import("@/db/schema");
	const tileCounts = await db
		.select({
			dashboardId: dashboardTiles.dashboardId,
			count: count(),
		})
		.from(dashboardTiles)
		.where(
			rows.length > 0
				? // Drizzle's inArray handles the list; empty list would crash
					// (SQL `IN ()` is invalid) — guarded by the rows.length check.
					(await import("drizzle-orm")).inArray(
						dashboardTiles.dashboardId,
						rows.map((r) => r.id),
					)
				: eq(
						dashboardTiles.dashboardId,
						"00000000-0000-0000-0000-000000000000",
					),
		)
		.groupBy(dashboardTiles.dashboardId);

	const countByDashboard = new Map(
		tileCounts.map((r) => [r.dashboardId, r.count]),
	);

	return NextResponse.json({
		dashboards: rows.map((r) => ({
			...r,
			tileCount: countByDashboard.get(r.id) ?? 0,
		})),
	});
}

interface CreateBody {
	name: string;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
	const session = await requireSession();

	if (!canEdit(session.role)) {
		return NextResponse.json(
			{ error: "viewers cannot create dashboards" },
			{ status: 403 },
		);
	}

	let body: CreateBody;
	try {
		body = (await req.json()) as CreateBody;
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}

	if (
		!body.name ||
		typeof body.name !== "string" ||
		body.name.trim().length === 0
	) {
		return NextResponse.json({ error: "name is required" }, { status: 422 });
	}
	if (body.name.trim().length > MAX_TITLE_LEN) {
		return NextResponse.json(
			{ error: `name must be at most ${MAX_TITLE_LEN} characters` },
			{ status: 422 },
		);
	}

	const tenantDbId = await upsertTenantId(session.tenantId);

	// Soft cap: prevent unbounded dashboard accumulation.
	const [existing] = await db
		.select({ count: count() })
		.from(dashboards)
		.where(eq(dashboards.tenantId, tenantDbId));
	if ((existing?.count ?? 0) >= MAX_DASHBOARDS) {
		return NextResponse.json(
			{ error: `workspace already has ${MAX_DASHBOARDS} dashboards` },
			{ status: 422 },
		);
	}

	const [row] = await db
		.insert(dashboards)
		.values({
			tenantId: tenantDbId,
			name: body.name.trim(),
			createdBy: session.email,
		})
		.returning();

	return NextResponse.json(row, { status: 201 });
}
