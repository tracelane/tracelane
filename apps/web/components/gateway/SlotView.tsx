"use client";

import dynamic from "next/dynamic";
import { CacheSettings } from "./CacheSettings";
import { OtelExports } from "./OtelExports";

const RoutingEditor = dynamic(
	() => import("./RoutingEditor").then((module) => module.RoutingEditor),
	{ ssr: false },
);
const GuardrailIntegrations = dynamic(
	() =>
		import("./GuardrailIntegrations").then(
			(module) => module.GuardrailIntegrations,
		),
	{ ssr: false },
);
const GuardrailPolicyEditor = dynamic(
	() =>
		import("./GuardrailPolicyEditor").then(
			(module) => module.GuardrailPolicyEditor,
		),
	{ ssr: false },
);

const DataControls = dynamic(
	() => import("./DataControls").then((m) => m.DataControls),
	{ ssr: false },
);

const McpControls = dynamic(
	() => import("./McpControls").then((m) => m.McpControls),
	{ ssr: false },
);
const Approvals = dynamic(
	() => import("./Approvals").then((m) => m.Approvals),
	{ ssr: false },
);

export function SlotView({
	slot,
}: {
	slot: { id: string; label: string; probe: string };
}) {
	if (slot.id === "mcp") return <McpControls />;
	if (slot.id === "approvals") return <Approvals />;
	if (slot.id === "data-controls") return <DataControls />;
	if (slot.id === "cache") return <CacheSettings />;
	if (slot.id === "otel") return <OtelExports />;
	if (slot.id === "routing") return <RoutingEditor />;
	if (slot.id === "guardrails") return <GuardrailPolicyEditor />;
	if (slot.id === "guardrail-integrations") return <GuardrailIntegrations />;
	return null;
}
