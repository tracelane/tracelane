/**
 * apps/site/src/data/product-data.ts — THE single source for /product and its four pages.
 *
 * 2026-09-27. Every item is something a customer can use TODAY in the deployed product,
 * extracted from the code by a read-only pass and spot-checked by hand (each has a code
 * anchor in the internal ledger's 2026-09-27 handover). `proven: true` only where a
 * production proof is on record — the same rule as changelog-data.ts.
 *
 * Deliberately absent: the similarity tier of the response cache (built, never served a
 * request), zero-data-retention routing (built, but no provider is rated eligible yet, so
 * it would refuse every request), prompt/response text capture for customers (decided,
 * not built). No number appears here that is not already sourced on the site
 * (overhead: index.astro benchRows, from apps/docs/benchmarks.mdx; provider count: held by check-provider-count.py).
 */

export type Feature = { title: string; use: string; proven?: boolean };

export type Section = {
	slug: "gateway" | "observability" | "audit" | "evals";
	name: string;
	/** The pillar question the section answers — the same six as the changelog. */
	why: string;
	headline: string;
	lede: string;
	/** One sourced proof point shown in the hero. */
	stat: { value: string; label: string; source: string };
	features: Feature[];
	doc: string;
};

export const SECTIONS: Section[] = [
	{
		slug: "gateway",
		name: "Gateway",
		why: "Control — one endpoint that routes, caps and swaps models, changed in settings, not in code.",
		headline: "One endpoint for every model you use.",
		lede: "Point your OpenAI or Anthropic client at Tracelane. Your calls go to your provider with your own key, every one of them is recorded, and the routing is yours to change without a deploy.",
		stat: {
			value: "2 / 4 / 5 ms",
			label: "added at p50 / p95 / p99, under steady traffic",
			source: "AIGatewayBench, 2026-09-07, two runs on a 4-vCPU host",
		},
		features: [
			{
				title: "OpenAI-compatible endpoint",
				use: "Change one base URL; any OpenAI-compatible client works, and every call is traced.",
			},
			{
				title: "Anthropic-native endpoint",
				use: "Point Claude Code or any Anthropic client straight at the gateway and get full tracing, tokens and cost.",
				proven: true,
			},
			{
				title: "Your keys, 0% markup",
				use: "Store provider keys encrypted per workspace, check on demand that a key still works, and pay your provider directly.",
			},
			{
				title: "Name your own models",
				use: 'Call a model by a name you control, like "fast", and repoint it in settings — the trace records both names.',
				proven: true,
			},
			{
				title: "Failover you configure",
				use: "Turn on cross-provider failover for your whole workspace and choose the fallback models, in order.",
			},
			{
				title: "Exact-match response cache",
				use: "Serve an identical repeated request from cache; a response header says it was cached.",
				proven: true,
			},
			{
				title: "Guardrails at the gateway",
				use: "Guardrail rails check requests at the gateway — cost and step caps, secrets and personal data, tool pinning, format and topic — and flag or redact what matches. Which rails you get depends on your plan.",
			},
			{
				title: "Breakers and a real cost per call",
				use: "Each provider gets its own circuit breaker, and every call carries its USD cost from a model price catalogue.",
			},
		],
		doc: "https://docs.tracelane.dev/quickstart",
	},
	{
		slug: "observability",
		name: "Observability",
		why: "Visibility — when an agent misbehaves, the answer is already recorded.",
		headline: "See what your agents actually did.",
		lede: "Every call, tool and retry, readable as the conversation it was — searchable, shareable, and in the OpenTelemetry format you already use.",
		stat: {
			value: "OTel",
			label: "native — OTLP in, GenAI conventions",
			source: "send OTLP directly; spans follow the OpenTelemetry GenAI semantic conventions",
		},
		features: [
			{
				title: "Search and slice traces",
				use: "Search by span name or content, filter, group and sort, and export what you see to CSV or JSON.",
				proven: true,
			},
			{
				title: "Traces read as conversations",
				use: "Read a trace as the transcript it was, with the span tree and an inspector beside it.",
			},
			{
				title: "One lane per agent",
				use: "See multi-agent runs with a lane per sub-agent and a failures-only filter.",
				proven: true,
			},
			{
				title: "Every retry and failover hop",
				use: "See each attempt a request made — retries and failover hops with status and timing — not only the one that worked.",
				proven: true,
			},
			{
				title: "Know every calling agent",
				use: "See which agents and clients call your gateway, each with its own profile and history.",
				proven: true,
			},
			{
				title: "Traces by your end user",
				use: "Send your own user id and filter sessions and traces by the person who started them.",
				proven: true,
			},
			{
				title: "Share one trace",
				use: "Send a revocable, account-free link to a single trace, with its ledger badge.",
				proven: true,
			},
			{
				title: "Dashboards, SLOs and alerts",
				use: "Build your own dashboards, read latency and error SLOs, and route alerts to Slack, Discord or a webhook.",
				proven: true,
			},
		],
		doc: "https://docs.tracelane.dev",
	},
	{
		slug: "audit",
		name: "Audit ledger",
		why: "Proof — evidence a third party can verify offline, without trusting us.",
		headline: "A record your auditor can check without us.",
		lede: "Every call through the gateway, and every policy result on it, goes onto a tamper-evident hash chain for your workspace, signed with your workspace's own key and anchored to a public transparency log. Spans you send directly over OTLP or an SDK are recorded, not chained.",
		stat: {
			value: "3",
			label: "independent offline verifiers",
			source: "Rust, Python and TypeScript — run without network access",
		},
		features: [
			{
				title: "Tamper-evident ledger",
				use: "Every gateway call and policy result is chained, so a later edit, deletion or reorder is detectable.",
			},
			{
				title: "Signed with your workspace's key",
				use: "Batches are signed with a key that belongs to your workspace, not one shared across customers.",
			},
			{
				title: "Anchored to a public log",
				use: "Batch roots are anchored in the public Sigstore Rekor log, which anyone can look up.",
			},
			{
				title: "Verify offline, three languages",
				use: "Verify an exported bundle with no network access, in Rust, Python or TypeScript.",
			},
			{
				title: "A verifier an auditor runs",
				use: "Hand an auditor one signed binary that exits non-zero when the chain does not hold.",
			},
			{
				title: "Verify on any plan",
				use: "Check your chain in the product at no cost, including a recompute in your own browser.",
			},
			{
				title: "Written in one transaction",
				use: "Each ledger row is committed in the same database transaction as the chain it extends, and archived hourly.",
				proven: true,
			},
			{
				title: "EU AI Act Article 12 export (Enterprise)",
				use: "On Enterprise, export the record-keeping pack mapped obligation by obligation; an export that cannot complete fails loudly instead of handing you half. Per-record inclusion proofs and a signed completeness attestation are on the roadmap.",
			},
		],
		doc: "https://docs.tracelane.dev/audit-ledger",
	},
	{
		slug: "evals",
		name: "Evals",
		why: "Quality — prove a prompt or model change is better before it reaches users.",
		headline: "Ship prompt changes you can defend.",
		lede: "Turn production traces into test cases, score live traffic, and let CI refuse a change that falls below the floor you set.",
		stat: {
			value: "CI",
			label: "gate on your own floor",
			source: "the eval gate fails a build when quality falls below a threshold you set",
		},
		features: [
			{
				title: "A CI eval gate",
				use: "Fail a pull request when a dataset's score falls below your floor — with separate exit codes for \"worse\" and \"couldn't measure\".",
				proven: true,
			},
			{
				title: "Score live traffic",
				use: "Let an LLM judge score a sampled share of production traffic, under a spend cap you set.",
				proven: true,
			},
			{
				title: "Canary a prompt version",
				use: "Send a new prompt version to a share of your users, each kept on the same version, before promoting it.",
				proven: true,
			},
			{
				title: "Versioned prompts, signed changes",
				use: "Version prompts and promote or roll back; every change is a signed record in your ledger.",
			},
			{
				title: "Review queues",
				use: "Send failing traces to a queue, write the right answer, and keep it as a test case.",
				proven: true,
			},
			{
				title: "Datasets from production",
				use: "Keep datasets that persist, and add a trace's input from the trace page in one click.",
			},
			{
				title: "Compare against a baseline",
				use: "Compare an experiment against a baseline case by case, not only on the average.",
			},
			{
				title: "Playground to trace",
				use: "Try a prompt against your connected provider and land on the trace it produced.",
				proven: true,
			},
		],
		doc: "https://docs.tracelane.dev/eval-gates",
	},
];
