// Tracelane design system (@tracelanedev/ui). src/styles/tokens.css is the SINGLE
// definition of colour, type and layout — this file describes none of it on purpose.
// Import the token layer once in the consuming app:  import "@tracelanedev/ui/styles/tokens.css";

export { cn } from "./lib/cn";
// The ONE duration formatter. It lived in apps/web until 2026-08-16, which forced
// TimeRuler (in this package) to either duplicate its rules or disagree with the bar
// labels beside it — and two trace-viewer surfaces had already grown their own copies.
export { fmtDur, fmtDurMs } from "./lib/fmt-dur";

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
// Hover/focus detail. The repo had NO tooltip or popover before 2026-08-19 — the
// only hover affordance anywhere was the native `title=` attribute, which is
// slow, unstyleable, and invisible on touch.
export { Tooltip, type TooltipProps } from "./primitives/Tooltip";
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
	// The ONE span-kind value ramp. Exported because `apps/web`'s waterfall marks the
	// same kinds and used to keep its own copy — the two drifted the moment the palette
	// moved. See the map's own comment for why it is value, not hue.
	SPAN_KIND_MARK,
} from "./signature/TranscriptSpine";
export {
	LatencyTimeline,
	type LatencyTimelineProps,
	type LatencyPoint,
} from "./signature/LatencyTimeline";

// ── ADR-074 additions ────────────────────────────────────────────────────────
export {
	BarChart,
	type BarChartProps,
	type BarDatum,
	type BarTone,
} from "./charts/BarChart";
export { StatGrid, type StatGridProps } from "./primitives/StatGrid";
// THE table system. One header height, one row height, one hover, one alignment rule.
// It replaced 21 hand-rolled tables that between them had seven `<thead>` treatments
// and three different row hovers — see the component for the measurement.
export {
	Table,
	THead,
	TBody,
	TR,
	TH,
	TD,
	TDetail,
	type TRProps,
	type THProps,
	type TDProps,
} from "./primitives/Table";
// THE one-of-N control. It replaced nine hand-rolled copies, eight of which painted
// the selected option as a solid ink pill — see the component for why that is wrong
// for one-of-N specifically, and still right for the primary button.
export {
	SegmentedControl,
	type SegmentedControlProps,
	type SegmentedOption,
} from "./primitives/SegmentedControl";
// Extracted from StatCard (DSH-08) the moment a second surface wanted the shape.
export { SparkBars, type SparkBarsProps } from "./charts/SparkBars";
export {
	LedgerSeqChip,
	TimeRuler,
	type TimeRulerProps,
} from "./signature/TimeRuler";
