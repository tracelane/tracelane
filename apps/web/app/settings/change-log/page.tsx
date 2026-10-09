import { ChangeLog } from "@/components/gateway/ChangeLog";
import { RoleScope } from "@/components/gateway/RoleScope";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Change log — Settings" };

export default function Page() {
	return (
		<RoleScope>
			<ChangeLog />
		</RoleScope>
	);
}
