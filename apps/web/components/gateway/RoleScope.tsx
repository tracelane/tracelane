import { requireSession } from "@/lib/auth";
import type { ReactNode } from "react";
import { RoleProvider } from "./control";

/** Server wrapper: hands the signed-in role to the client islands (UI gating only). */
export async function RoleScope({ children }: { children: ReactNode }) {
	const session = await requireSession();
	return <RoleProvider role={session.role}>{children}</RoleProvider>;
}
