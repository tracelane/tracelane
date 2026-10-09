import { AdminAccess, RoleMatrix } from "@/components/gateway/AdminAccess";
import { RoleScope } from "@/components/gateway/RoleScope";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Security — Settings" };

export default function Page() {
	return (
		<RoleScope>
			<div className="space-y-6">
				<AdminAccess />
				<RoleMatrix />
			</div>
		</RoleScope>
	);
}
