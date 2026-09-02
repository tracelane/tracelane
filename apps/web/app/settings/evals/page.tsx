/**
 * /settings/evals — online evals (`EVL-28`, Sprint 3 item 11).
 *
 * Sample live production traffic, grade it with the LLM judge that item 10
 * shipped, and show what it cost. Gated on `f_online_evals`.
 *
 * ── WHY THE UNENTITLED STATE IS SHOWN, NOT HIDDEN ───────────────────────────
 *
 * A workspace without the grant sees the real card with a real description and
 * an upgrade path — never a missing nav entry and never a blank page. Hiding a
 * gated feature makes the plan boundary invisible, which is the
 * `invisible-entitlement-gated-ui` failure: a customer cannot ask for something
 * they have no evidence exists.
 *
 * tenant_id comes exclusively from the WorkOS session; never from the request.
 */

import { OnlineEvalsManager } from "@/components/settings/OnlineEvalsManager";
import { db } from "@/db";
import { tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { type Plan, resolveEntitlements } from "@/lib/entitlements";
import { eq } from "drizzle-orm";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Online evals — Settings" };
export const dynamic = "force-dynamic";

async function isOnlineEvalsEntitled(): Promise<boolean> {
	const session = await requireSession();
	const [row] = await db
		.select({ id: tenants.id, plan: tenants.plan })
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);
	const plan: Plan = (row?.plan as Plan) ?? "free";
	const entitlements = await resolveEntitlements(row?.id, plan);
	return entitlements.f_online_evals;
}

function OnlineEvalsUpsell() {
	return (
		<div className="rounded-lg border border-dashed border-line p-10 text-center space-y-3">
			<h3 className="text-sm font-semibold text-ink">
				Online evals are available on a higher plan
			</h3>
			<p className="text-xs text-ink-2 max-w-md mx-auto">
				Score a sample of your live production traffic with an LLM judge, on a
				rubric you choose, running on your own provider key. Every policy
				carries a required monthly spend ceiling, and the judge never touches
				the request path — it runs after the response is already sent.
			</p>
			<a
				href="/settings/billing"
				className="inline-block text-xs font-medium text-action-ink hover:underline"
			>
				View plans →
			</a>
		</div>
	);
}

export default async function OnlineEvalsPage() {
	const entitled = await isOnlineEvalsEntitled();

	return (
		<div className="space-y-1">
			<h2 className="text-sm font-semibold text-ink">Online evals</h2>
			<p className="text-xs text-ink-2 mb-6">
				Grade a sample of live traffic against a rubric. Judging happens after
				the response is sent, so it never adds latency to a request — and it
				spends from your workspace wallet, under a cap you set.
			</p>
			{entitled ? <OnlineEvalsManager /> : <OnlineEvalsUpsell />}
		</div>
	);
}
