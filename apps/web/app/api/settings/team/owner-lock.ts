import { Pool } from "@neondatabase/serverless";
import { sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/neon-serverless";
import { NextResponse } from "next/server";

/** Serialize membership reads and writes across workers in the same workspace.
 * The HTTP database driver cannot hold an interactive transaction across WorkOS
 * calls, so this path uses the installed WebSocket driver. Fail CLOSED if the
 * lock cannot be acquired. WorkOS remains an external transaction boundary.
 */
export async function withOwnerMutation(
	orgId: string,
	mutate: () => Promise<NextResponse>,
): Promise<NextResponse> {
	let pool: Pool | undefined;
	try {
		const connectionString = process.env.DATABASE_URL;
		if (!connectionString) throw new Error("database not configured");
		pool = new Pool({ connectionString });
		return await drizzle(pool).transaction(async (tx) => {
			await tx.execute(
				sql`SELECT pg_advisory_xact_lock(hashtextextended(${`tracelane:owners:${orgId}`}, 0))`,
			);
			return mutate();
		});
	} catch {
		// No database URL, credentials or external response bodies in the log.
		console.error("[team/owners] serialized membership change failed");
		return NextResponse.json(
			{
				error: "membership_change_unavailable",
				message:
					"Could not confirm the membership change. Refresh the team before retrying.",
			},
			{ status: 503 },
		);
	} finally {
		await pool?.end().catch(() => {
			console.error("[team/owners] database connection cleanup failed");
		});
	}
}
