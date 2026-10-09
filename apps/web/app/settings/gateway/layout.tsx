import { GatewayTabs } from "@/components/gateway/GatewayTabs";
import { RoleScope } from "@/components/gateway/RoleScope";
import { detectSlots } from "@/lib/gateway-slots";
import type { ReactNode } from "react";

// Reads the session and probes the gateway — never prerender.
export const dynamic = "force-dynamic";

export default async function GatewayLayout({
	children,
}: { children: ReactNode }) {
	const slots = await detectSlots();
	return (
		<RoleScope>
			<GatewayTabs slots={slots.map((s) => ({ id: s.id, label: s.label }))} />
			{children}
		</RoleScope>
	);
}
