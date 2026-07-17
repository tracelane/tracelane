/**
 * GET  /api/settings/provider-keys — list the tenant's stored LLM provider
 *      keys (provider_id + last4 only; ciphertext never leaves the gateway).
 * POST /api/settings/provider-keys — upload / overwrite a provider key
 *      (sk-ant-…, sk-…, etc.) for a given provider.
 *
 * Thin proxy to the Rust gateway's `/v1/byok/provider-keys`, which envelope-
 * encrypts the key (AES-256-GCM, AAD-bound to tenant+provider) and persists
 * only the ciphertext + last4. The WorkOS access token is forwarded as Bearer;
 * the gateway bridges its `org_id` → internal tenant UUID (ADR-042 bug #2).
 *
 * The plaintext key is forwarded once and never logged or persisted by the
 * dashboard. Upstream error bodies are never echoed (a gateway/provider error
 * could reference the key) — we map to generic messages.
 *
 * NOTE: "provider keys" (your upstream `sk-ant-`/`sk-` credentials) are
 * DISTINCT from CMK / "Encryption Keys" at `/settings/byok`, which are the
 * customer-managed keys that envelope-encrypt data at rest.
 */

import { requireGatewayToken } from "@/lib/auth";
import { type NextRequest, NextResponse } from "next/server";

const GATEWAY = process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8080";

interface ProviderKeySummary {
	provider_id: string;
	last4: string;
}

export async function GET(): Promise<NextResponse> {
	const { token } = await requireGatewayToken();

	const upstream = await fetch(`${GATEWAY}/v1/byok/provider-keys`, {
		headers: { authorization: `Bearer ${token}` },
		cache: "no-store",
	});

	if (!upstream.ok) {
		return NextResponse.json(
			{ error: "provider keys unavailable" },
			{ status: upstream.status >= 500 ? 502 : upstream.status },
		);
	}

	const data = (await upstream.json()) as ProviderKeySummary[];
	return NextResponse.json(data);
}

interface UploadBody {
	provider_id: string;
	plaintext: string;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
	const { token } = await requireGatewayToken();

	let body: UploadBody;
	try {
		body = (await req.json()) as UploadBody;
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}

	const providerId = body.provider_id?.trim();
	// Keys are pasted; trim accidental surrounding whitespace (provider keys
	// never contain leading/trailing whitespace) so a stray newline can't
	// silently break auth later.
	const plaintext = body.plaintext?.trim();
	if (!providerId || !plaintext) {
		return NextResponse.json(
			{ error: "provider_id and key are required" },
			{ status: 422 },
		);
	}

	const upstream = await fetch(`${GATEWAY}/v1/byok/provider-keys`, {
		method: "POST",
		headers: {
			authorization: `Bearer ${token}`,
			"content-type": "application/json",
		},
		// tenant is NEVER sent in the body — the gateway derives it from the
		// JWT. Only the provider id + the key plaintext cross the wire.
		body: JSON.stringify({ provider_id: providerId, plaintext }),
	});

	if (!upstream.ok) {
		const status =
			upstream.status === 400
				? 400
				: upstream.status >= 500
					? 502
					: upstream.status;
		return NextResponse.json(
			{
				error:
					status === 400
						? "unknown or unsupported provider"
						: "failed to store provider key",
			},
			{ status },
		);
	}

	const data = (await upstream.json()) as ProviderKeySummary;
	return NextResponse.json(data);
}
