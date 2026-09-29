"use client";

/**
 * Client-side provider tree.
 *
 * Wraps the app with TanStack Query's QueryClientProvider.
 * All data fetching in client components uses the shared client.
 */

import { ApiError } from "@/lib/api-fetch";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useState } from "react";

/**
 * Retry a genuine fault (5xx, or a network error with no `ApiError` at all —
 * a fetch that never reached a server), never a client error. A 403/404 is
 * not going to change its mind on a second try; retrying it just cost the
 * customer ~5s of skeleton before the SAME answer renders (item 11).
 */
export function shouldRetry(failureCount: number, error: unknown): boolean {
	if (failureCount >= 2) return false;
	if (error instanceof ApiError) return error.status >= 500;
	return true;
}

export function Providers({ children }: { children: ReactNode }) {
	const [queryClient] = useState(
		() =>
			new QueryClient({
				defaultOptions: {
					queries: {
						staleTime: 30_000,
						retry: shouldRetry,
					},
				},
			}),
	);

	return (
		<QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
	);
}
