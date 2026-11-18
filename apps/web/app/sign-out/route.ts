import { signOut } from "@workos-inc/authkit-nextjs";
import { getURLFromRedirectError } from "next/dist/client/components/redirect";
import { isRedirectError } from "next/dist/client/components/redirect-error";

export const dynamic = "force-dynamic";

// A route and page cannot occupy the same Next.js segment. GET only opens the
// confirmation page; it never reads or changes the user's session.
export function GET(): Response {
	return new Response(null, {
		status: 303,
		headers: { Location: "/sign-out/confirm", "Cache-Control": "no-store" },
	});
}

export async function POST(request: Request): Promise<Response> {
	let origin: string;
	try {
		const configured = new URL(
			process.env.NEXT_PUBLIC_WORKOS_REDIRECT_URI ?? "",
		);
		if (!["http:", "https:"].includes(configured.protocol)) throw new Error();
		origin = configured.origin;
	} catch {
		return Response.json({ error: "Sign out unavailable" }, { status: 503 });
	}
	if (request.headers.get("origin") !== origin) {
		return Response.json({ error: "Forbidden" }, { status: 403 });
	}
	const returnTo = `${origin}/sign-in`;
	try {
		// AuthKit 4.0.1 owns session + PKCE cleanup and ALWAYS redirects. Adapt
		// only Next's typed redirect, keeping SDK cookie policy in one place.
		await signOut({ returnTo });
	} catch (error) {
		if (isRedirectError(error)) {
			const target = getURLFromRedirectError(error);
			return Response.json(
				{ logout_url: target === returnTo ? "/sign-in" : target },
				{ headers: { "Cache-Control": "no-store" } },
			);
		}
	}
	return Response.json({ error: "Sign out unavailable" }, { status: 503 });
}
