// Tracelane Neon design system (@tracelanedev/ui) — ADR-045 / the design-system spec.
// Import the token layer once in the consuming app:  import "@tracelanedev/ui/styles/tokens.css";

export { cn } from "./lib/cn";

// primitives
export { Button, type ButtonProps } from "./primitives/Button";
export { Card, type CardProps } from "./primitives/Card";
export {
	StatCard,
	type StatCardProps,
	type StatTone,
	type StatVariant,
} from "./primitives/StatCard";
export { Logo, type LogoProps } from "./primitives/Logo";
export {
	MetricIcon,
	type MetricIconName,
	type MetricIconProps,
} from "./primitives/MetricIcon";
export { Badge, type BadgeProps } from "./primitives/Badge";
export { Skeleton } from "./primitives/Skeleton";
export { EmptyState, type EmptyStateProps } from "./primitives/EmptyState";
export { ErrorState, type ErrorStateProps } from "./primitives/ErrorState";

// charts (app design system) — thin-line/rings/lollipop/gauge, token-colored
export {
	ConcentricRings,
	type ConcentricRing,
	type ConcentricRingsProps,
} from "./charts/ConcentricRings";
export {
	Lollipop,
	type LollipopPoint,
	type LollipopProps,
} from "./charts/Lollipop";
export { Gauge, type GaugeProps } from "./charts/Gauge";
export {
	RequestFlow,
	type RequestFlowModel,
	type RequestFlowProps,
} from "./charts/RequestFlow";
export {
	ModelDonut,
	type ModelDonutSegment,
	type ModelDonutProps,
} from "./charts/ModelDonut";
export {
	AgentGraph,
	type AgentGraphNode,
	type AgentGraphProps,
} from "./charts/AgentGraph";

// the three signature visualizations (the purple cow)
export {
	HashChainThread,
	ProvenanceChip,
	type HashChainThreadProps,
	type ProvenanceChipProps,
} from "./signature/HashChainThread";
export {
	SeenBeforeSignal,
	type SeenBeforeSignalProps,
} from "./signature/SeenBeforeSignal";
export {
	TranscriptSpine,
	type TranscriptSpineProps,
	type SpanNode,
	type SpanKind,
} from "./signature/TranscriptSpine";
export {
	LatencyTimeline,
	type LatencyTimelineProps,
	type LatencyPoint,
} from "./signature/LatencyTimeline";
