/**
 * GET    /api/dashboards/[id]          — get a single dashboard.
 * PATCH  /api/dashboards/[id]          — rename it (editor+).
 * DELETE /api/dashboards/[id]          — delete it and its tiles (editor+).
 *
 * Another tenant's id → 404, never 403 (tenant isolation — the id reveals
 * nothing about ownership to someone who probes with a foreign id).
 */

import { db } from "@/db";
import { dashboardTiles, dashboards } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { upsertTenantId } from "@/lib/tenant";
import { and, eq, inArray } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

function canEdit(role: string | null | undefined): boolean {
	return role === "owner" || role === "admin" || role === "member";
}

const MAX_TITLE_LEN = 60;

interface Params {
	params: Promise<{ id: string }>;
}

export async function GET(
	_req: NextRequest,
	{ params }: Params,
): Promise<NextResponse> {
	const { id } = await params;
	const session = await requireSession();
	const tenantDbId = await upsertTenantId(session.tenantId);

	const [row] = await db
		.select()
		.from(dashboards)
		.where(and(eq(dashboards.id, id), eq(dashboards.tenantId, tenantDbId)))
		.limit(1);

	if (!row) {
		// 404, not 403 — tenant isolation: a foreign id is indistinguishable from
		// a non-existent one (the same pattern as annotation-queues, experiments).
		return NextResponse.json({ error: "not found" }, { status: 404 });
	}

	const tiles = await db
		.select()
		.from(dashboardTiles)
		.where(eq(dashboardTiles.dashboardId, id))
		.orderBy(dashboardTiles.position);

	return NextResponse.json({ ...row, tiles });
}

interface PatchBody {
	name?: string;
}

export async function PATCH(
	req: NextRequest,
	{ params }: Params,
): Promise<NextResponse> {
	const { id } = await params;
	const session = await requireSession();

	if (!canEdit(session.role)) {
		return NextResponse.json(
			{ error: "viewers cannot rename dashboards" },
			{ status: 403 },
		);
	}

	let body: PatchBody;
	try {
		body = (await req.json()) as PatchBody;
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}

	if (body.name !== undefined) {
		if (typeof body.name !== "string" || body.name.trim().length === 0) {
			return NextResponse.json(
				{ error: "name must be a non-empty string" },
				{ status: 422 },
			);
		}
		if (body.name.trim().length > MAX_TITLE_LEN) {
			return NextResponse.json(
				{ error: `name must be at most ${MAX_TITLE_LEN} characters` },
				{ status: 422 },
			);
		}
	}

	const tenantDbId = await upsertTenantId(session.tenantId);

	// Verify tenant owns this dashboard before updating.
	const [existing] = await db
		.select({ id: dashboards.id })
		.from(dashboards)
		.where(and(eq(dashboards.id, id), eq(dashboards.tenantId, tenantDbId)))
		.limit(1);

	if (!existing) {
		return NextResponse.json({ error: "not found" }, { status: 404 });
	}

	const updates: Partial<typeof dashboards.$inferInsert> = {
		updatedAt: new Date(),
	};
	if (body.name !== undefined) {
		updates.name = body.name.trim();
	}

	const [updated] = await db
		.update(dashboards)
		.set(updates)
		.where(and(eq(dashboards.id, id), eq(dashboards.tenantId, tenantDbId)))
		.returning();

	return NextResponse.json(updated);
}

export async function DELETE(
	_req: NextRequest,
	{ params }: Params,
): Promise<NextResponse> {
	const { id } = await params;
	const session = await requireSession();

	if (!canEdit(session.role)) {
		return NextResponse.json(
			{ error: "viewers cannot delete dashboards" },
			{ status: 403 },
		);
	}

	const tenantDbId = await upsertTenantId(session.tenantId);

	const [existing] = await db
		.select({ id: dashboards.id })
		.from(dashboards)
		.where(and(eq(dashboards.id, id), eq(dashboards.tenantId, tenantDbId)))
		.limit(1);

	if (!existing) {
		return NextResponse.json({ error: "not found" }, { status: 404 });
	}

	// ON DELETE CASCADE on the FK handles tiles; explicit delete is belt-and-suspenders
	// and makes the intent visible in the query log.
	await db.delete(dashboardTiles).where(eq(dashboardTiles.dashboardId, id));
	await db
		.delete(dashboards)
		.where(and(eq(dashboards.id, id), eq(dashboards.tenantId, tenantDbId)));

	return new NextResponse(null, { status: 204 });
}
