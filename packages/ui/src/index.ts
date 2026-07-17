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
} from "./primitives/StatCard";
export { Logo, type LogoProps } from "./primitives/Logo";
export { Badge, type BadgeProps } from "./primitives/Badge";
export { Skeleton } from "./primitives/Skeleton";
export { EmptyState, type EmptyStateProps } from "./primitives/EmptyState";
export { ErrorState, type ErrorStateProps } from "./primitives/ErrorState";

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
