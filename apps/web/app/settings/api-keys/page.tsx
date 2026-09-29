/**
 * /settings/api-keys — API key management page.
 *
 * Server component shell; delegates to ApiKeyManager client component
 * for list/create/rotate/revoke interactions. SET-38: it passes the session's
 * role and user id down, so the client can apply the "who may edit this key's
 * limits" rule (owner: any key; member: keys they minted). UI gating only — the
 * gateway re-decides every edit.
 */

import { ApiKeyManager } from "@/components/settings/ApiKeyManager";
import { requireSession } from "@/lib/auth";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "API Keys — Settings" };

export default async function ApiKeysPage() {
	const session = await requireSession();
	return (
		<ApiKeyManager viewer={{ role: session.role, userId: session.userId }} />
	);
}
