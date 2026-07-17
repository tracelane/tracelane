/**
 * /prompts — list of named prompts for the authenticated tenant.
 *
 * RSC. Fetches GET /v1/prompts from the gateway (per-user JWT). Three states:
 *   - Loading: Suspense skeleton
 *   - Error (gateway unreachable): ErrorState
 *   - Empty (reachable but no prompts): EmptyPrompts component
 *   - Data: table of prompts with env badges + version counts
 *
 * tenant_id is resolved by the gateway from the WorkOS JWT — the dashboard
 */

import { DeletePromptButton } from "@/app/prompts/DeletePromptButton";
import { NewPromptForm } from "@/app/prompts/NewPromptForm";
import { EmptyPrompts } from "@/components/empty-states/EmptyPrompts";
import { db } from "@/db";
import { tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { type Plan, resolveEntitlements } from "@/lib/entitlements";
import { fetchPromptList } from "@/lib/prompts";
import { Badge, ErrorState, Skeleton } from "@tracelanedev/ui";
import { eq } from "drizzle-orm";
import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";

/**
 * Plan-gate banner — the Team-tier gate must be visible on the LIST page, not
 * discovered on the detail page's PromotionPanel 403. Reads the REAL
 * `prompt_promotion_write` entitlement (never a tier string-compare, CLAUDE.md
 * ban). Honest copy: Builder can VIEW (read=true), promoting needs Team+.
 */
async function PromoteGateBanner() {
	const session = await requireSession();
	const [row] = await db
		.select({ id: tenants.id, plan: tenants.plan })
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);
	const plan: Plan = (row?.plan as Plan) ?? "free";
	const ent = await resolveEntitlements(row?.id, plan);
	if (ent.prompt_promotion_write) return null;
	return (
		<div className="mb-4 flex flex-wrap items-center gap-2 rounded-lg border border-line bg-surface-2/40 px-4 py-2.5 text-sm text-ink-2">
			<span>
				<span className="font-medium text-ink">
					Promoting a version across environments requires Team ($249/mo)
				</span>{" "}
				— viewing and authoring versions is free.
			</span>
			<Link
				href="/settings/billing"
				className="ml-auto font-medium text-accent-ink hover:underline"
			>
				Upgrade →
			</Link>
		</div>
	);
}

export const metadata: Metadata = { title: "Prompts — Tracelane" };
export const dynamic = "force-dynamic";

/** Env → badge tone mapping. Kept limited; unknown envs fall back to neutral. */
const ENV_TONE: Record<string, "ok" | "accent" | "seal" | "warn" | "neutral"> =
	{
		production: "ok",
		staging: "accent",
		canary: "seal",
		dev: "warn",
	};

function formatDate(ms: number): string {
	if (!Number.isFinite(ms) || ms <= 0) return "—";
	return new Date(ms).toLocaleDateString("en-US", {
		month: "short",
		day: "numeric",
		year: "numeric",
	});
}

async function PromptListData() {
	const list = await fetchPromptList();

	if (list === null) {
		return (
			<ErrorState
				title="Gateway unreachable"
				description="Could not reach the gateway. Check that NEXT_PUBLIC_GATEWAY_URL is set and the gateway is running, then reload."
			/>
		);
	}

	if (list.length === 0) {
		return <EmptyPrompts />;
	}

	return (
		<div className="overflow-x-auto rounded-lg border border-line">
			<table className="w-full text-sm">
				<thead className="bg-surface-2/50">
					<tr>
						<th className="px-4 py-3 text-left font-medium text-ink-2">Name</th>
						<th className="px-4 py-3 text-right font-medium text-ink-2">
							Versions
						</th>
						<th className="px-4 py-3 text-left font-medium text-ink-2">
							Active
						</th>
						<th className="px-4 py-3 text-right font-medium text-ink-2">
							Updated
						</th>
						<th className="px-4 py-3 text-right font-medium text-ink-2">
							<span className="sr-only">Actions</span>
						</th>
					</tr>
				</thead>
				<tbody className="divide-y divide-line">
					{list.map((prompt) => (
						<tr
							key={prompt.prompt_id}
							className="transition-colors hover:bg-surface-2/30"
						>
							<td className="px-4 py-3">
								<Link
									href={`/prompts/${encodeURIComponent(prompt.name)}`}
									className="font-mono font-medium text-ink hover:text-accent-ink hover:underline"
								>
									{prompt.name}
								</Link>
							</td>
							<td className="px-4 py-3 text-right font-mono tabular-nums text-ink-2">
								{prompt.versions}
							</td>
							<td className="px-4 py-3">
								<div className="flex flex-wrap gap-1.5">
									{prompt.active.length === 0 ? (
										<span className="text-xs text-ink-3">none</span>
									) : (
										prompt.active.map((a) => (
											<Badge key={a.env} tone={ENV_TONE[a.env] ?? "neutral"}>
												{a.env} v{a.version_number}
											</Badge>
										))
									)}
								</div>
							</td>
							<td className="px-4 py-3 text-right text-xs tabular-nums text-ink-2">
								{formatDate(prompt.updated_at_ms)}
							</td>
							<td className="px-4 py-3 text-right">
								<DeletePromptButton name={prompt.name} />
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}

const SKELETON_KEYS = ["sk-0", "sk-1", "sk-2", "sk-3"] as const;

function PromptListSkeleton() {
	return (
		<div className="space-y-2">
			{SKELETON_KEYS.map((k) => (
				<Skeleton key={k} className="h-12 w-full" />
			))}
		</div>
	);
}

export default function PromptsListPage() {
	return (
		<main className="mx-auto max-w-5xl p-6">
			<div className="mb-6 flex flex-col items-start gap-4 sm:flex-row sm:justify-between">
				<div>
					<h1 className="text-2xl font-semibold text-ink">Prompts</h1>
					<p className="mt-1 max-w-xl text-sm text-ink-2">
						Version a prompt, then promote it across environments — every
						promotion is written to the tamper-evident audit ledger. Name a
						prompt to author its first version.
					</p>
				</div>
				<NewPromptForm />
			</div>
			<Suspense fallback={null}>
				<PromoteGateBanner />
			</Suspense>
			<Suspense fallback={<PromptListSkeleton />}>
				<PromptListData />
			</Suspense>
		</main>
	);
}
