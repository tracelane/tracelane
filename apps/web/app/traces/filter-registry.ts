/** One declared URL grammar for trace links, controls and downloads. */
export const TRACE_FILTERS = [
	{
		param: "key",
		gatewayParam: "key",
		kind: "value",
		label: "API key",
		ownerSpec: "trace-list",
		export: true,
	},
	{
		param: "loop",
		gatewayParam: "loop",
		kind: "enum",
		label: "Repeated tool calls",
		ownerSpec: "agent-loops",
		export: true,
	},
	{
		param: "rescued",
		gatewayParam: "rescued",
		kind: "enum",
		label: "Rescued",
		ownerSpec: "rescue-evidence",
		export: true,
	},
	{
		param: "has_error",
		gatewayParam: "has_error",
		kind: "enum",
		label: "Error status",
		ownerSpec: "trace-list",
		export: true,
	},
	{
		param: "issue",
		gatewayParam: "issue",
		kind: "enum",
		label: "Generation issue",
		ownerSpec: "generation-issues",
		export: true,
	},
	{
		param: "status",
		gatewayParam: "has_error",
		kind: "enum",
		label: "Status",
		ownerSpec: "trace-list",
		export: true,
	},
	{
		param: "model",
		gatewayParam: "model",
		kind: "value",
		label: "Model",
		ownerSpec: "trace-list",
		export: true,
	},
	{
		param: "environment",
		gatewayParam: "environment",
		kind: "value",
		label: "Environment",
		ownerSpec: "request-labels",
		export: true,
	},
	{
		param: "release",
		gatewayParam: "release",
		kind: "value",
		label: "Release",
		ownerSpec: "request-labels",
		export: true,
	},
	{
		param: "service",
		gatewayParam: "service",
		kind: "value",
		label: "Service",
		ownerSpec: "request-labels",
		export: true,
	},
	{
		param: "tag",
		gatewayParam: "tag",
		kind: "value",
		label: "Tag",
		ownerSpec: "request-labels",
		export: true,
	},
	{
		param: "meta",
		gatewayParam: "meta",
		kind: "value",
		label: "Metadata",
		ownerSpec: "request-labels",
		export: true,
	},
	{
		param: "range",
		gatewayParam: null,
		kind: "window",
		label: "Range",
		ownerSpec: "trace-list",
		export: true,
	},
	{
		param: "since",
		gatewayParam: null,
		kind: "window",
		label: "Since",
		ownerSpec: "trace-list",
		export: true,
	},
	{
		param: "until",
		gatewayParam: null,
		kind: "window",
		label: "Until",
		ownerSpec: "trace-list",
		export: true,
	},
	{
		param: "min_latency_ms",
		gatewayParam: "min_latency_ms",
		kind: "value",
		label: "Latency",
		ownerSpec: "trace-list",
		export: true,
	},
	{
		param: "signature_id",
		gatewayParam: "signature_id",
		kind: "value",
		label: "Signature",
		ownerSpec: "trace-list",
		export: true,
	},
	{
		param: "q",
		gatewayParam: "q",
		kind: "value",
		label: "Search",
		ownerSpec: "trace-list",
		export: true,
	},
	{
		param: "failover",
		gatewayParam: "failover",
		kind: "enum",
		label: "Failover",
		ownerSpec: "trace-list",
		export: true,
	},
	{
		param: "end_user",
		gatewayParam: "end_user",
		kind: "value",
		label: "User",
		ownerSpec: "trace-list",
		export: true,
	},
	{
		param: "agent",
		gatewayParam: "agent",
		kind: "value",
		label: "Agent",
		ownerSpec: "trace-list",
		export: true,
	},
	{
		param: "model_family",
		gatewayParam: "model_family",
		kind: "value",
		label: "Model family",
		ownerSpec: "trace-list",
		export: true,
	},
	{
		param: "sort",
		gatewayParam: "sort",
		kind: "sort",
		label: "Sort",
		ownerSpec: "trace-list",
		export: true,
	},
	{
		param: "order",
		gatewayParam: "order",
		kind: "sort",
		label: "Order",
		ownerSpec: "trace-list",
		export: true,
	},
	{
		param: "group",
		gatewayParam: "by",
		kind: "view",
		label: "Group",
		ownerSpec: "trace-list",
		export: false,
	},
	{
		param: "size",
		gatewayParam: "limit",
		kind: "view",
		label: "Page size",
		ownerSpec: "trace-list",
		export: false,
	},
	{
		param: "cursor",
		gatewayParam: "cursor",
		kind: "view",
		label: "Continuation",
		ownerSpec: "trace-list",
		export: true,
	},
] as const;

export type TraceParam = (typeof TRACE_FILTERS)[number]["param"];
export const TRACE_PAGE_PARAMS = TRACE_FILTERS.map((entry) => entry.param);
export const TRACE_EXPORT_PARAMS = TRACE_FILTERS.filter(
	(entry) => entry.export,
);

export function traceFilter(param: string) {
	return TRACE_FILTERS.find((entry) => entry.param === param);
}

export function traceFilterLabel(param: TraceParam): string {
	return traceFilter(param)?.label ?? param;
}

type Source = URLSearchParams | Record<string, string | undefined>;
type GatewayMode = "list" | "export" | "group" | "stream";

/** Copy only declared gateway parameters. The gateway binds values or parses enums. */
export function copyGatewayTraceFilters(
	target: URLSearchParams,
	source: Source,
	mode: GatewayMode,
): void {
	const get = (param: TraceParam) =>
		source instanceof URLSearchParams ? source.get(param) : source[param];
	for (const entry of TRACE_FILTERS) {
		if (!entry.gatewayParam || entry.param === "status") continue;
		if (mode === "export" && !entry.export) continue;
		if (
			(mode === "group" || mode === "stream") &&
			["q", "sort", "order", "cursor"].includes(entry.param)
		)
			continue;
		const value = get(entry.param);
		if (!value || (entry.param === "failover" && value !== "true")) continue;
		target.set(entry.gatewayParam, value);
	}
	const status = get("status");
	if (status === "error") target.set("has_error", "true");
	else if (status === "ok") target.set("has_error", "false");
}
