/**
 * GET  /api/dashboards/[id]/tiles   — list tiles for a dashboard.
 * POST /api/dashboards/[id]/tiles   — add a tile (editor+).
 *
 * Tile add validates:
 *   - metric_id ∈ registry keys
 *   - shape ∈ {stat, series, breakdown, divider}
 *   - width ∈ {4, 6, 12}
 *   - height ∈ {compact, regular, tall} (default `regular` — matches the
 *     column default, so an older client that never sends it keeps working)
 *   - dimension ∈ the closed list (required for breakdown, forbidden otherwise)
 *   - title ≤ 60 chars
 *
 * `shape: "divider"` (DSH-13 §9, 2026-09-07) is a pure-layout tile — a full-
 * width section header/rule, no metric, no fetch. It branches BEFORE the
 * registry/`shapeSupported` checks (which do not apply to it — it is not a
 * metric+shape composition) and is pinned server-side to
 * `metric_id: "__divider__"` / `width: 12` / `height: "compact"`; any other
 * value for those three fields on a divider tile is a 400 naming the field,
 * and the sentinel metric_id is refused on every OTHER shape (it is reserved,
 * not a hidden extra metric).
 *
 * tenant_id comes from the session → internal UUID via upsertTenantId; a
 * dashboard id that does not belong to this tenant returns 404.
 */

import { db } from "@/db";
import { dashboardTiles, dashboards } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { METRICS } from "@/lib/metrics/registry";
import {
	DIVIDER_METRIC_ID,
	DIVIDER_SHAPE,
	shapeSupported,
	tileSupport,
} from "@/lib/metrics/tile-support";
import { upsertTenantId } from "@/lib/tenant";
import { and, count, eq, max } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

function canEdit(role: string | null | undefined): boolean {
	return role === "owner" || role === "admin" || role === "member";
}

const VALID_SHAPES = new Set([
	"stat",
	"series",
	"breakdown",
	DIVIDER_SHAPE,
] as const);
const VALID_WIDTHS = new Set([4, 6, 12] as const);
const VALID_HEIGHTS = new Set(["compact", "regular", "tall"] as const);
const VALID_DIMENSIONS = new Set([
	"model",
	"provider",
	"api_key",
	"status",
	"operation",
	"decision",
	"rail",
] as const);
const MAX_TILES = 12;
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

	// Verify dashboard belongs to this tenant.
	const [dashboard] = await db
		.select({ id: dashboards.id })
		.from(dashboards)
		.where(and(eq(dashboards.id, id), eq(dashboards.tenantId, tenantDbId)))
		.limit(1);

	if (!dashboard) {
		return NextResponse.json({ error: "not found" }, { status: 404 });
	}

	const tiles = await db
		.select()
		.from(dashboardTiles)
		.where(eq(dashboardTiles.dashboardId, id))
		.orderBy(dashboardTiles.position);

	return NextResponse.json({ tiles });
}

interface AddTileBody {
	title?: string;
	metric_id: string;
	shape: string;
	dimension?: string;
	filter_dimension?: string;
	filter_value?: string;
	width?: number;
	height?: string;
}

export async function POST(
	req: NextRequest,
	{ params }: Params,
): Promise<NextResponse> {
	const { id } = await params;
	const session = await requireSession();

	if (!canEdit(session.role)) {
		return NextResponse.json(
			{ error: "viewers cannot add tiles" },
			{ status: 403 },
		);
	}

	let body: AddTileBody;
	try {
		body = (await req.json()) as AddTileBody;
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}

	// ── Validate shape first — a divider skips the metric/shape-matrix checks ──
	if (!body.shape || !VALID_SHAPES.has(body.shape as "stat")) {
		return NextResponse.json(
			{ error: "shape must be stat, series, breakdown, or divider" },
			{ status: 422 },
		);
	}
	const isDivider = body.shape === DIVIDER_SHAPE;

	let width: number;
	let height: string;
	if (isDivider) {
		// ── Divider: pure layout, no metric, one fixed size ────────────────────
		if (body.metric_id !== DIVIDER_METRIC_ID) {
			return NextResponse.json(
				{
					error: `divider tiles must use metric_id "${DIVIDER_METRIC_ID}"`,
					field: "metric_id",
				},
				{ status: 400 },
			);
		}
		if (body.width !== undefined && body.width !== 12) {
			return NextResponse.json(
				{
					error:
						"divider tiles are always 12 columns wide — width must be 12 or omitted",
					field: "width",
				},
				{ status: 400 },
			);
		}
		if (body.height !== undefined && body.height !== "compact") {
			return NextResponse.json(
				{
					error:
						'divider tiles are always compact height — height must be "compact" or omitted',
					field: "height",
				},
				{ status: 400 },
			);
		}
		if (body.dimension) {
			return NextResponse.json(
				{
					error: "dimension is not valid for divider tiles",
					field: "dimension",
				},
				{ status: 400 },
			);
		}
		width = 12;
		height = "compact";
	} else {
		// ── Every other shape: the sentinel metric_id is reserved, not a metric ─
		if (body.metric_id === DIVIDER_METRIC_ID) {
			return NextResponse.json(
				{
					error: `metric_id "${DIVIDER_METRIC_ID}" is reserved for divider tiles — use shape "divider"`,
					field: "metric_id",
				},
				{ status: 400 },
			);
		}
		// ── Validate metric_id against the registry ────────────────────────────
		if (!body.metric_id || !(body.metric_id in METRICS)) {
			return NextResponse.json(
				{
					error: `metric_id must be one of: ${Object.keys(METRICS).join(", ")}`,
				},
				{ status: 422 },
			);
		}

		// ── Validate width ──────────────────────────────────────────────────────
		width = body.width ?? 6;
		if (!VALID_WIDTHS.has(width as 4 | 6 | 12)) {
			return NextResponse.json(
				{ error: "width must be 4, 6, or 12" },
				{ status: 422 },
			);
		}

		// ── Validate height ─────────────────────────────────────────────────────
		height = body.height ?? "regular";
		if (!VALID_HEIGHTS.has(height as "compact" | "regular" | "tall")) {
			return NextResponse.json(
				{ error: "height must be compact, regular, or tall" },
				{ status: 422 },
			);
		}

		// ── Validate dimension ──────────────────────────────────────────────────
		if (body.shape === "breakdown") {
			if (!body.dimension || !VALID_DIMENSIONS.has(body.dimension as "model")) {
				return NextResponse.json(
					{
						error: `breakdown tiles require dimension ∈ [${[...VALID_DIMENSIONS].join(", ")}]`,
					},
					{ status: 422 },
				);
			}
		} else if (body.dimension) {
			return NextResponse.json(
				{ error: "dimension is only valid for breakdown tiles" },
				{ status: 422 },
			);
		}
		// The closed matrix: not every metric supports every shape (a series-only metric has no
		// single number; `verdicts` breaks down by decision/rail, not by provider). Refused here
		// so a saved tile can never render "unsupported".
		if (!shapeSupported(body.metric_id, body.shape, body.dimension)) {
			const sup = tileSupport(body.metric_id);
			return NextResponse.json(
				{
					error: `${body.metric_id} does not support shape ${body.shape}${body.shape === "breakdown" ? ` by ${body.dimension}` : ""}`,
					supports: {
						stat: sup.stat,
						series: sup.series,
						breakdown_dimensions: sup.breakdownDimensions,
					},
				},
				{ status: 422 },
			);
		}
	}

	// ── Validate title (label, for a divider) ──────────────────────────────────
	const title = body.title ?? "";
	if (title.length > MAX_TITLE_LEN) {
		return NextResponse.json(
			{ error: `title must be at most ${MAX_TITLE_LEN} characters` },
			{ status: 422 },
		);
	}

	const tenantDbId = await upsertTenantId(session.tenantId);

	// Verify dashboard ownership.
	const [dashboard] = await db
		.select({ id: dashboards.id })
		.from(dashboards)
		.where(and(eq(dashboards.id, id), eq(dashboards.tenantId, tenantDbId)))
		.limit(1);

	if (!dashboard) {
		return NextResponse.json({ error: "not found" }, { status: 404 });
	}

	// Enforce tile cap.
	const [tileCount] = await db
		.select({ count: count() })
		.from(dashboardTiles)
		.where(eq(dashboardTiles.dashboardId, id));
	if ((tileCount?.count ?? 0) >= MAX_TILES) {
		return NextResponse.json(
			{ error: `dashboard already has ${MAX_TILES} tiles (the maximum)` },
			{ status: 422 },
		);
	}

	// Update the dashboard's updated_at so the list re-sorts.
	await db
		.update(dashboards)
		.set({ updatedAt: new Date() })
		.where(eq(dashboards.id, id));

	// B-342: a concurrent add can land on the same position; the unique index refuses the
	// second, and we retry once with a fresh max instead of failing the user's click.
	let tile: typeof dashboardTiles.$inferSelect | undefined;
	for (let attempt = 0; attempt < 3 && !tile; attempt++) {
		const posRows = await db
			.select({ maxPos: max(dashboardTiles.position) })
			.from(dashboardTiles)
			.where(eq(dashboardTiles.dashboardId, id));
		const nextPosition = (posRows[0]?.maxPos ?? -1) + 1;
		try {
			[tile] = await db
				.insert(dashboardTiles)
				.values({
					dashboardId: id,
					position: nextPosition,
					width,
					height,
					title,
					metricId: body.metric_id,
					shape: body.shape,
					// A divider never carries a dimension or filter — forced here rather
					// than trusted from the body, even though the checks above already
					// refuse a non-empty `dimension` for one (spec §9.2).
					dimension: isDivider ? null : (body.dimension ?? null),
					filterDimension: isDivider ? null : (body.filter_dimension ?? null),
					filterValue: isDivider ? null : (body.filter_value ?? null),
				})
				.returning();
		} catch (err) {
			if ((err as { code?: string })?.code !== "23505" || attempt === 2)
				throw err;
		}
	}
	if (!tile) {
		return NextResponse.json(
			{ error: "could not place the tile — try again" },
			{ status: 409 },
		);
	}

	return NextResponse.json(tile, { status: 201 });
}
