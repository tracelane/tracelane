import { ReadFailure } from "@/components/empty-states/ReadFailure";
import { PolicyTemplates } from "@/components/settings/PolicyTemplates";
import { canAdmin, requireSession } from "@/lib/auth";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import type { ActivePolicy } from "@/lib/policy-templates";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Action policies — Settings" };
export const dynamic = "force-dynamic";

type Server = { id: string; name: string };

export default async function ActionPoliciesPage() {
	const session = await requireSession();
	let policies: (ActivePolicy & { server_name?: string })[];
	let servers: Server[];
	try {
		[policies, servers] = await Promise.all([
			gatewayGet<{ policies: ActivePolicy[] }>("/v1/action-policies").then(
				(r) => r.policies,
			),
			// Project to what the client needs: the raw rows carry more than the form uses.
			gatewayGet<{ servers: Server[] }>("/v1/mcp-servers").then((r) =>
				r.servers.map((s) => ({ id: s.id, name: s.name })),
			),
		]);
	} catch (err) {
		const status = err instanceof GatewayError ? err.status : 503;
		return (
			<div className="space-y-3">
				<h2 className="text-sm font-semibold text-ink">Action policies</h2>
				{status === 409 ? (
					<p role="alert" className="text-sm">
						Action control is off for this workspace. An owner can turn it on in
						Workspace settings.
					</p>
				) : (
					<ReadFailure
						status={status}
						resource="action policies"
						retryHref="/settings/action-policies"
					/>
				)}
			</div>
		);
	}
	const names = new Map(servers.map((s) => [s.id, s.name]));
	return (
		<div className="space-y-4">
			<h2 className="text-sm font-semibold text-ink">Action policies</h2>
			<p className="text-sm">
				{policies.length === 0
					? "No tools are protected yet. Start from a template below."
					: `${policies.length} protected ${policies.length === 1 ? "tool has" : "tools have"} a policy.`}
			</p>
			{policies.length > 0 && (
				<ul className="divide-y divide-line rounded-card border border-line">
					{policies.map((p) => (
						<li
							key={p.tool_ref}
							className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3 text-sm"
						>
							<span className="font-mono">{p.tool_name}</span>
							<span className="flex-1 text-ink-2">
								{names.get(p.server_id) ?? "Unknown server"}
							</span>
							<span className="text-xs text-ink-2">
								Policy version {p.policy_version}
							</span>
						</li>
					))}
				</ul>
			)}
			<PolicyTemplates
				servers={servers}
				policies={policies}
				canEdit={canAdmin(session.role)}
			/>
		</div>
	);
}
