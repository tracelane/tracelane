/**
 * /onboarding is for a SIGNED-IN user who has no workspace yet. The page is a client
 * component with no session guard of its own, and the middleware does not enforce
 * sign-in — so a signed-out visitor (an expired session, a bookmarked link) used to
 * land on the org-creation wizard. Signed out → /sign-in; signed in → the wizard.
 */
import { e2eAuthEnabled } from "@/lib/e2e-auth";
import { withAuth } from "@workos-inc/authkit-nextjs";
import { redirect } from "next/navigation";
import type { ReactNode } from "react";

export default async function OnboardingLayout({
	children,
}: {
	children: ReactNode;
}) {
	if (!e2eAuthEnabled()) {
		const auth = await withAuth().catch(() => null);
		// Outside any catch, so NEXT_REDIRECT is never swallowed.
		if (!auth?.user) redirect("/sign-in");
	}
	return children;
}
