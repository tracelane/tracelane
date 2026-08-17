import { SETTINGS_HREF } from "@/components/layout/nav-model";
import { redirect } from "next/navigation";

/**
 * `/settings` had NO page.tsx — only a layout — so the bare URL 404'd. Found by the
 * R12 before-inventory (docs/internal/R12_BEFORE_INVENTORY.md), not by a user report,
 * because nothing linked to `/settings` directly: every entry point pointed at a
 * sub-tab. A 404 nobody links to is invisible until somebody types the obvious URL.
 *
 * Redirects to the first tab rather than rendering a landing page: the settings rail
 * is the index, and a second index would be one more thing to keep in sync.
 */
export default function SettingsIndex() {
	redirect(SETTINGS_HREF);
}
