import { forwardParams } from "@/lib/gateway";

/** Legacy API proxy uses the same declared gateway window parameters. */
export function gatewayStatsProxyUrl(searchParams: URLSearchParams): string {
	return `/v1/gateway/stats?${forwardParams(searchParams, ["since", "until", "hours"])}`;
}
