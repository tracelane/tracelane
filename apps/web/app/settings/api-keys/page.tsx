/**
 * /settings/api-keys — API key management page.
 *
 * Server component shell; delegates to ApiKeyManager client component
 * for list/create/revoke interactions.
 */

import { ApiKeyManager } from "@/components/settings/ApiKeyManager";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "API Keys — Settings" };

export default function ApiKeysPage() {
	return <ApiKeyManager />;
}
