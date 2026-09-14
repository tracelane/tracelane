/**
 * apps/site/src/data/changelog-data.ts
 *
 * THE SINGLE SOURCE for the public /changelog page. The page renders this file
 * and holds no prose of its own — one place to correct a claim, one place a
 * reviewer has to read.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * HOW THIS WAS DERIVED, AND WHERE IT IS THIN
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * WINDOW: 2026-05-02 → 2026-09-07.
 *
 *   The brief asked for 2026-04-07 → 2026-09-07. The repository's FIRST COMMIT
 *   is `811b22d5`, dated 2026-04-29 (`git log --reverse --date=short`), so
 *   2026-04-07 → 2026-04-28 has nothing to report and no entry is invented for
 *   it. That first day is 56 commits of a squashed import covering "Week 1"
 *   through "Week 7" of prior work — an IMPORT date, not a build date — so
 *   nothing is dated to it either. The first date a customer could act on is
 *   the 0.1.0 release, 2026-05-02 (`CHANGELOG.md:472`).
 *
 * TWO SPINES, JOINED AT 2026-07-29:
 *
 *   BEFORE 2026-07-29 — derived from `CHANGELOG.md`'s dated sections
 *   (`[0.1.0] - 2026-05-02` at :472, the 2026-05-23 pricing retrofit at :360,
 *   the five 2026-05-26 gap-closure patches at :281-356, the 2026-06-10/-11
 *   sections at :237-280, `[0.2.2]`/`[0.2.3] - 2026-08-01` at :120,:167) and
 *   from `git log --format='%ad|%s' --date=short` filtered to `feat`/`perf`
 *   subjects. NO FEATURE ID (`OBS-`/`GWY-`/`EVL-`/`DSH-`/`PLT-`/`SET-`/`AUD-`)
 *   APPEARS IN ANY COMMIT SUBJECT BEFORE 2026-07-29 — the id scheme did not
 *   exist yet — so entries in this half carry no `id`, and their state is
 *   `"shipped"` unless a production proof is separately recorded.
 *
 *   FROM 2026-07-29 — taken from the verified reconciliation in
 *   `BUILT_SINCE_LAUNCH.md` (44 ids, git-derived at HEAD `d1ae0069`,
 *   cross-checked against the internal inventory and ledger), plus
 *   the internal ledger's 2026-09-07 (h)/(i)/(j) handovers for blocks 9 through 12.
 *
 * `state: "proven"` IS NOT A SYNONYM FOR "SHIPPED". It is set ONLY where a
 * PRODUCTION proof is recorded in the internal ledger or roadmap
 * or `BUILT_SINCE_LAUNCH.md` — a real row read back out of prod, a real request
 * against the live gateway, a rendered surface measured at a real viewport.
 * Everything else is `"shipped"`: built, deployed, not independently re-proven.
 * A built-but-undeployed change appears in NEITHER state and is simply absent.
 *
 * AGGREGATED HARD, ON PURPOSE. 758 commits and ~107 named defects since go-live
 * alone collapse to the 66 entries below. Every follow-up fix, re-proof and
 * internal correction is folded into the feature it belongs to and dated by the
 * day that feature became usable, not by its last commit. The unaggregated
 * record already exists internally; this page is the progress story.
 *
 * DELIBERATELY OMITTED, not forgotten:
 *   · The quota-alert-at-full-plan-usage claim. the internal ledger records it
 *     BUILT+LIVE-PROVEN; the internal inventory records "There is NO
 *     automatic alert". Two canonical trackers contradict each other, so the
 *     claim is dropped rather than guessed (`BUILT_SINCE_LAUNCH.md` Finding 1).
 *   · The near-duplicate ("semantic") tier of the response cache. Built, but it
 *     has never served a request in production — 0 rows, ever. Only the
 *     exact-match tier is claimed.
 *   · Metered overage billing. Built and deployed, blocked in production on a
 *     provider token scope, so no customer is billed for overage.
 *   · Full request/response content capture. Switched on for one internal
 *     tenant only.
 *   · Per-plan retention ENFORCEMENT. The entitlement-aware sweep exists but
 *     ships OFF, so nothing is actually deleted for anyone yet; only the fixed
 *     backstop is real. Claiming "kept for your plan's window" would describe a
 *     control that is not running.
 *   · The notifications bell. The surface is built, but two of its three alert
 *     producers are not wired, so "see every alert that fired" is not true yet.
 *   · Anything reverted (a 2026-08-21 visual pass shipped and was reverted the
 *     same day), and every id a commit subject names but never delivered.
 *
 * COPY CONSTRAINTS THAT BIND THIS FILE — not style, enforced. The banned strings
 * are DELIBERATELY NOT REPRODUCED HERE, only pointed at: `.astro` files get a
 * comment_filter exemption for naming a banned phrase in order to forbid it
 * (`scripts/export/pre-public-push.sh`, the PricingTable.astro case), and that
 * guard's own selftest asserts the exemption does NOT widen past `.astro`. A
 * `.ts` file spelling the literals out is therefore a landmine for any future
 * widening. Read the ledgers, do not copy them here:
 *
 *   1. `scripts/deploy/site.sh:78-85` — the built-HTML content manifest. Seven
 *      banned strings, globbed over the built HTML at the dist root AND one
 *      level down, so `dist/changelog/index.html` IS in scope. ONE OF THEM IS
 *      A TRAP FOR THIS
 *      PAGE: our npm scope contains a substring that is banned because the
 *      matching social handle has never existed. The homepage was reworded for
 *      exactly this on 2026-09-07 (`01d7a96e`). NO NPM PACKAGE IS NAMED WITH ITS
 *      SCOPE ANYWHERE BELOW, and that is not an oversight — do not "fix" it.
 *   2. `.claude/skills/public-copy/SKILL.md` — the honesty locks. Notably: the
 *      ledger is evidence-of-tampering, never proof-against it; policy is
 *      enforced AT the gateway, never described as pre-empting a failure; no
 *      absolute percentage; no guardrail COUNT as a headline; no performance
 *      number without a published measurement behind it; the provider claim is
 *      hedged and the hedge floor is set by `docs/inventory/CLAIM_ANCHORS.json`.
 *   3. `scripts/export/pre-public-push.sh` `scan_docs()` reads `.astro` (B-340b)
 *      but NOT `.ts` — the banned-phrase scan sees the page's markup, never this
 *      data. For these strings the control is the `public-copy` checklist plus a
 *      `verifier` pass, by hand. Said out loud so nobody assumes a guard.
 */

export type EntryType =
	| "gateway"
	| "observability"
	| "evals"
	| "trust"
	| "platform";

export type Entry = {
	/** ISO date. The day it became real for a customer, not the commit date. */
	date: string;
	/** 3-6 words. The thing itself, never the ticket. */
	title: string;
	/**
	 * ONE sentence: what a customer can now DO. Written for someone who has never
	 * seen our internals. Never "we refactored X" — always "you can now Y".
	 */
	use: string;
	type: EntryType;
	/**
	 * "proven"  — a production proof is on record (see the header).
	 * "shipped" — built and deployed; no independent production proof recorded.
	 */
	state: "shipped" | "proven";
	/** Internal id where one exists. Rendered as a small monospace tag, nothing more. */
	id?: string;
	/**
	 * Path on docs.tracelane.dev. ONLY set where the page is CONFIRMED live there,
	 * which needs two things and both were checked per link:
	 *   (a) the `.mdx` predates the last public-mirror promotion (2026-09-02) —
	 *       so `/benchmarks`, `/ask-tara` and `/integrations/claude-code` are
	 *       deliberately absent; authored 2026-09-06/07, they go in at the next
	 *       promotion; and
	 *   (b) the page is in `apps/docs/docs.json`'s navigation — which
	 *       `audit/verifier-cli` and `compliance/eu-ai-act-article-12` are NOT,
	 *       despite existing as PUBLIC files, so neither is linked either.
	 * Shipping a 404 from the page whose whole argument is that we check our
	 * claims would be the worst possible defect on it.
	 */
	doc?: string;
};

export const TYPE_LABEL: Record<EntryType, string> = {
	gateway: "Gateway",
	observability: "Observability",
	evals: "Evals",
	trust: "Trust",
	platform: "Platform",
};

/** Newest first. The page groups by month; it does not re-sort. */
export const ENTRIES: Entry[] = [
	// ─── September 2026 ────────────────────────────────────────────────────────
	{
		date: "2026-09-07",
		title: "Gateway overhead, measured",
		use: "See exactly what the gateway costs you in latency — 2 ms at the median, 5 ms at the 99th — measured on LiteLLM's open benchmark harness rather than one we wrote.",
		type: "gateway",
		state: "proven",
		id: "PLT-23",
	},
	{
		date: "2026-09-07",
		title: "OpenAI tool calling, end to end",
		use: "Run an agent that calls tools through the gateway with the OpenAI SDK unchanged — real tool calls come back, the finish reason is the true one, and you can replay the model's own tool call in the next turn.",
		type: "gateway",
		state: "proven",
	},
	{
		date: "2026-09-07",
		title: "Dashboards you build yourself",
		use: "Assemble your own dashboard from a palette of metric tiles, then resize, move and remove them — the layout persists across a reload.",
		type: "observability",
		state: "proven",
		id: "DSH-13",
	},
	{
		date: "2026-09-07",
		title: "Truncated answers are never cached",
		use: "Ask again after a reply was cut short by a token limit and you get a fresh, complete answer instead of the truncated one served back from cache.",
		type: "gateway",
		state: "proven",
	},
	{
		date: "2026-09-07",
		title: "Self-hosting runs unmetered",
		use: "Run the gateway on your own hardware with no control plane and it no longer applies the hosted free tier's request limit to your traffic.",
		type: "platform",
		state: "proven",
		doc: "/self-hosting",
	},
	{
		date: "2026-09-06",
		title: "Anthropic-native endpoint",
		use: "Point Claude Code, or any Anthropic-native client, straight at the gateway and get full tracing, token counts and cost with no OpenAI-shape translation in between.",
		type: "gateway",
		state: "proven",
		id: "GWY-47",
	},
	{
		date: "2026-09-06",
		title: "Ask your traces a question",
		use: "Type a question about your own runs in plain English and get an answer, instead of writing the query yourself.",
		type: "observability",
		state: "shipped",
		id: "OBS-40",
	},
	{
		date: "2026-09-06",
		title: "Multi-agent runs, as swim lanes",
		use: "Read a run with sub-agents as one labelled lane per agent, with a failures-only filter, rather than as a single flat timeline.",
		type: "observability",
		state: "proven",
		id: "OBS-49",
	},
	{
		date: "2026-09-06",
		title: "Shareable trace links",
		use: "Send someone a link to one trace, carrying its ledger badge, that they can open without an account — and revoke it when you are done.",
		type: "observability",
		state: "proven",
		id: "OBS-48",
	},
	{
		date: "2026-09-06",
		title: "Search the trace list",
		use: "Find a trace by span name or content from a search box on the traces page, instead of paging until you spot it.",
		type: "observability",
		state: "proven",
		id: "OBS-01",
	},
	{
		date: "2026-09-06",
		title: "A playground inside the app",
		use: "Try a prompt against a provider you have connected and land straight on the trace it produced.",
		type: "evals",
		state: "proven",
		id: "EVL-03",
	},
	{
		date: "2026-09-06",
		title: "Claude Code sessions record fully",
		use: "See real token counts, computed cost, tool names and session grouping for a Claude Code session — all four were previously blank.",
		type: "observability",
		state: "proven",
		id: "PLT-46",
	},
	{
		date: "2026-09-06",
		title: "MCP for hosted workspaces",
		use: "Query your own traces from any MCP client using your bearer token — this previously needed a self-hosted deployment with a direct database connection.",
		type: "platform",
		state: "proven",
		id: "PLT-22",
		doc: "/mcp-server",
	},
	{
		date: "2026-09-05",
		title: "Your trace ids survive the gateway",
		use: "Call the gateway from your own instrumented app and the two halves join into one trace, instead of appearing as two disconnected ones.",
		type: "platform",
		state: "proven",
		id: "GWY-46",
	},
	{
		date: "2026-09-04",
		title: "Line and area charts",
		use: "Read latency percentiles, availability and error rate as a continuous line rather than as bars, which is the right shape for a level instead of a count.",
		type: "observability",
		state: "shipped",
		id: "DSH-14",
	},
	{
		date: "2026-09-02",
		title: "One time range for the dashboard",
		use: "Move one control and every chart on the dashboard answers to it, drawing a real interactive chart — several displays used to disagree with each other.",
		type: "observability",
		state: "proven",
		id: "DSH-11",
	},

	// ─── August 2026 ───────────────────────────────────────────────────────────
	{
		date: "2026-08-31",
		title: "Guides for the agent frameworks",
		use: "Get traces out of LangChain, LangGraph, CrewAI or LlamaIndex by pointing their existing OpenTelemetry exporter at us — no Tracelane-specific code, and each guide states exactly what you get.",
		type: "platform",
		state: "shipped",
		doc: "/integrations/langchain",
	},
	{
		date: "2026-08-30",
		title: "An eval gate for your CI",
		use: 'Run a dataset through your prompt on every pull request and fail the build when the score falls below a floor you set, with a separate exit code for "it got worse" and "we could not measure it".',
		type: "evals",
		state: "proven",
		id: "EVL-30",
		doc: "/eval-gates",
	},
	{
		date: "2026-08-29",
		title: "Review queues for failures",
		use: "Route a trace an automated judge scored as failing to a review queue, write the correct answer by hand, and keep it as a reusable test case.",
		type: "evals",
		state: "proven",
		id: "EVL-29",
	},
	{
		date: "2026-08-27",
		title: "Score live traffic automatically",
		use: "Have an automated judge score a share of your production traffic against a rubric you choose, at a sample rate you set, under a spend limit that survives a restart.",
		type: "evals",
		state: "proven",
		id: "EVL-28",
	},
	{
		date: "2026-08-24",
		title: "Nine ways to assert an eval",
		use: "Assert on contains, regex, JSON schema, an LLM judge, and cost and latency ceilings through the API — and a judge answer that does not match its schema errors instead of quietly scoring.",
		type: "evals",
		state: "shipped",
		id: "EVL-23",
		doc: "/eval-gates",
	},
	{
		date: "2026-08-23",
		title: "Datasets that persist",
		use: "Save a collection of test cases and have it still be there afterwards — every dataset write had been failing silently.",
		type: "evals",
		state: "shipped",
		id: "EVL-04",
	},
	{
		date: "2026-08-20",
		title: "Repeat requests served from cache",
		use: "Send the same request twice and the second is answered from the gateway's own cache instead of the provider, with a response header naming the tier that served it.",
		type: "gateway",
		state: "proven",
		id: "GWY-25",
	},
	{
		date: "2026-08-18",
		title: "Failover honours your config",
		use: "Set a fallback provider in `tracelane.yaml` and it is actually used — the setting had been read and then ignored.",
		type: "gateway",
		state: "shipped",
		id: "GWY-44",
	},
	{
		date: "2026-08-13",
		title: "Send OpenTelemetry traces directly",
		use: "Export a nested agent trace straight from your own instrumentation with your API key, and see the whole tree — planner step, each tool call, the retry — without proxying the model call.",
		type: "platform",
		state: "proven",
		id: "GWY-41",
		doc: "/sdk-typescript",
	},
	{
		date: "2026-08-12",
		title: "Compare two traces",
		use: "Open two runs side by side and see what differs between them.",
		type: "observability",
		state: "shipped",
		id: "OBS-10",
	},
	{
		date: "2026-08-11",
		title: "Three permission gaps closed",
		use: "A viewer can no longer promote or delete a production prompt, SSO and directory-sync setup is limited to the plan that includes it, and a billing-portal return address is checked against an allowlist.",
		type: "platform",
		state: "shipped",
	},
	{
		date: "2026-08-01",
		title: "Releases you can verify",
		use: "Check any release binary yourself — 0.2.3 is the first to publish a Cosign keyless signature and a CycloneDX SBOM per artifact, with build provenance attested by GitHub.",
		type: "trust",
		state: "shipped",
		doc: "/security",
	},

	// ─── July 2026 ─────────────────────────────────────────────────────────────
	{
		date: "2026-07-17",
		title: "Gemini through Vertex AI",
		use: "Route Gemini models via Google's Vertex AI endpoint with your own project credentials.",
		type: "gateway",
		state: "shipped",
		doc: "/providers",
	},
	{
		date: "2026-07-15",
		title: "Self-host without a certificate authority",
		use: "Run a single-tenant deployment without standing up SPIRE first, which removes the heaviest prerequisite from the self-host path.",
		type: "platform",
		state: "shipped",
		doc: "/self-hosting",
	},
	{
		date: "2026-07-15",
		title: "Verify your chain on any plan",
		// pricing-guard: allow "audit add-on" historical — a dated changelog entry (CLAUDE.md §19); the add-on was retired 2026-09-12
		use: "Check your workspace's hash chain from inside the product without paying for the audit add-on; the exportable, offline-verifiable bundle stays part of that add-on.",
		type: "trust",
		state: "shipped",
		doc: "/audit-ledger",
	},
	{
		date: "2026-07-14",
		title: "Slice the trace list",
		use: "Filter, group by model, operation or status, sort by any column, set one date range for the page, and export what you are looking at to CSV or JSON.",
		type: "observability",
		state: "shipped",
	},
	{
		date: "2026-07-13",
		title: "Anchored to a public log",
		use: "Prove to a third party that a batch of your records existed when you say it did — the first Merkle root reached the public Sigstore transparency log at index 19398597, and anyone can look it up without asking us.",
		type: "trust",
		state: "shipped",
		doc: "/audit-ledger",
	},
	{
		date: "2026-07-13",
		title: "Failure signatures from your traces",
		use: "See the failure shapes actually detected in your own runs, each with a first-seen and last-seen, rather than a catalogue of failures in the abstract.",
		type: "observability",
		state: "shipped",
	},
	{
		date: "2026-07-12",
		title: "Offline verification, three languages",
		use: "Hand an exported bundle to someone with no network access and let them verify it in Rust, Python or TypeScript against your own public key, served from a public endpoint so the trust root is not us.",
		type: "trust",
		state: "shipped",
		doc: "/audit-ledger",
	},
	{
		date: "2026-07-12",
		title: "Promotions are signed records",
		use: "Promote or roll back a prompt and the decision is appended to the tamper-evident chain as a signed verdict you can hand to someone else.",
		type: "evals",
		state: "shipped",
		doc: "/prompt-promotion",
	},
	{
		date: "2026-07-11",
		title: "Alerts you configure and test",
		use: "Write your own alert rules, send them to Slack, Discord or an HTTP endpoint, and fire a test to confirm the route works before you rely on it.",
		type: "observability",
		state: "shipped",
	},
	{
		date: "2026-07-10",
		title: "Teams, roles and seats",
		use: "Invite members, assign roles, stay inside the seat count your plan includes, and delete your own account or organisation without asking us.",
		type: "platform",
		state: "shipped",
	},
	{
		date: "2026-07-08",
		title: "Real cost on every call",
		use: "See the USD cost of a call on its span, in the trace list, and rolled into a spend card — computed from a model price catalogue rather than estimated.",
		type: "gateway",
		state: "shipped",
	},
	{
		date: "2026-07-07",
		title: "Sessions group a multi-turn run",
		use: "Follow a conversation across its turns as one session, with its own list and detail view, instead of as unrelated calls.",
		type: "observability",
		state: "shipped",
	},
	{
		date: "2026-07-07",
		title: "Prompts with durable versions",
		use: "Author a prompt, keep its versions, and promote one to production from the app — rather than keeping the text in your application code.",
		type: "evals",
		state: "shipped",
		doc: "/prompt-promotion",
	},
	{
		date: "2026-07-07",
		title: "A gateway operations page",
		use: "Watch per-provider health, failover state, circuit-breaker state and quota status from one page, with nothing on it that is not a measured signal.",
		type: "gateway",
		state: "shipped",
	},

	// ─── June 2026 ─────────────────────────────────────────────────────────────
	{
		date: "2026-06-24",
		title: "Sampling and quotas per workspace",
		use: "Set a sampling policy, an ingest quota and a per-trace ceiling for each workspace — and an over-quota batch is refused with the reason, never accepted and quietly dropped.",
		type: "platform",
		state: "shipped",
	},
	{
		date: "2026-06-21",
		title: "Spans acknowledged only after storage",
		use: "A restart mid-flight replays your span instead of losing it, because the queue is only acknowledged once the write has landed.",
		type: "platform",
		state: "shipped",
	},
	{
		date: "2026-06-20",
		title: "Pre-flight policy at the gateway",
		use: "Apply your own policy to a request before it leaves — cost and step caps, secret and PII patterns, tool pinning, response format and topic scope — and have it allowed, redacted or refused.",
		type: "gateway",
		state: "shipped",
		doc: "/predictive-guardrails",
	},
	{
		date: "2026-06-15",
		title: "A transcript-spine trace viewer",
		use: "Read a trace top to bottom as the conversation it was, with the span tree and an inspector beside it, and filter the list down to the run you are looking for.",
		type: "observability",
		state: "shipped",
	},
	{
		date: "2026-06-15",
		title: "Verify the ledger in your browser",
		use: "Watch your own browser recompute the chain and report the chain and signature verdicts separately — a passing badge is something your machine worked out, not something we asserted.",
		type: "trust",
		state: "shipped",
		doc: "/audit-ledger",
	},
	{
		date: "2026-06-15",
		title: "Onboarding ends in your own trace",
		use: "Finish setup by looking at the first trace your key actually produced, so the confirmation is your data rather than a checkmark.",
		type: "platform",
		state: "shipped",
		doc: "/onboarding",
	},
	{
		date: "2026-06-10",
		title: "A dropped span is loud",
		use: "Know when capture is broken: a span the gateway cannot record is counted, warned once and reported on the health endpoint, and an unset queue address refuses to start at all.",
		type: "observability",
		state: "shipped",
	},
	{
		date: "2026-06-08",
		title: "Tracelane Cloud is live",
		use: "Point a client at the hosted gateway and start capturing, instead of running the stack yourself first.",
		type: "platform",
		state: "shipped",
		doc: "/quickstart",
	},
	{
		date: "2026-06-02",
		title: "Cross-provider failover",
		use: "Name a fallback provider and a failing upstream is retried there, rather than the request ending at the first error.",
		type: "gateway",
		state: "shipped",
	},
	{
		date: "2026-06-02",
		title: "Tool-definition drift detection",
		use: "Find out when a tool's description or input schema changes underneath a running agent — the silent rug-pull an agent has no other way to notice.",
		type: "trust",
		state: "shipped",
		doc: "/predictive-guardrails",
	},

	// ─── May 2026 ──────────────────────────────────────────────────────────────
	{
		date: "2026-05-29",
		title: "Breakers, canaries and a kill switch",
		use: "Give each upstream its own circuit breaker, split traffic to a candidate prompt version, and turn a predictor off by name without a deploy.",
		type: "gateway",
		state: "shipped",
	},
	{
		date: "2026-05-26",
		title: "Ingest limits answered on the spot",
		use: "Send an oversized batch, span or attribute and get a synchronous refusal with the reason in a response header — nothing is accepted and then discarded behind your back.",
		type: "platform",
		state: "shipped",
	},
	{
		date: "2026-05-26",
		title: "A verifier a regulator can run",
		use: "Hand an auditor a single signed binary that verifies an exported ledger offline against a public key they pin themselves, and exits non-zero when the chain does not hold.",
		type: "trust",
		state: "shipped",
		doc: "/audit-ledger",
	},
	{
		date: "2026-05-24",
		title: "Pricing that states its limits",
		// Historical entry — describes the ADR-020 model that shipped THAT DAY,
		// superseded 2026-09-12 by ADR-076's six-meter model (CLAUDE.md §19:
		// supersession, never silent deletion — this record stays as written).
		// <!-- pricing-guard: allow "hard cap" -->
		use: "Read each plan's included volume, its per-unit overage with a hard cap, its seat ladder and its retention window on the page, instead of inferring them.",
		type: "platform",
		state: "shipped",
		doc: "/pricing",
	},
	{
		date: "2026-05-23",
		title: "Keys hashed, ledgers signed per workspace",
		use: "Your API keys are stored as Argon2id hashes behind a peppered lookup, and your ledger is signed with a key belonging to your workspace rather than a shared one.",
		type: "trust",
		state: "shipped",
	},
	{
		date: "2026-05-10",
		title: "Auto-instrumentation for Python and TypeScript",
		use: "Install the SDK and it attaches to the agent frameworks and provider clients you already use, so spans arrive without hand-written instrumentation.",
		type: "platform",
		state: "shipped",
		doc: "/sdk-python",
	},
	{
		date: "2026-05-10",
		title: "Traces, trace detail and SLO",
		use: "Browse your traces, open one to a span tree with an inspector, and read latency percentiles, error rate and token usage on an SLO page.",
		type: "observability",
		state: "shipped",
		doc: "/slo",
	},
	{
		date: "2026-05-07",
		title: "Prompt promotion with rollback",
		use: "Promote a prompt version to production atomically and have a drift detector roll it back — suggested, automatic or human-confirmed, your choice.",
		type: "evals",
		state: "shipped",
		doc: "/prompt-promotion",
	},
	{
		date: "2026-05-07",
		title: "Three independent verifiers",
		use: "Check an exported ledger in Rust, Python or TypeScript against shared conformance vectors, so whoever has to verify it can do so in a language they already run.",
		type: "trust",
		state: "shipped",
		doc: "/audit-ledger",
	},
	{
		date: "2026-05-02",
		title: "The gateway, in one binary",
		use: "Point any OpenAI-compatible client at one endpoint and your call is routed to your provider with your own key, traced and recorded — a model matching no provider is refused rather than sent somewhere by default.",
		type: "gateway",
		state: "shipped",
		doc: "/quickstart",
	},
	{
		date: "2026-05-02",
		title: "A tamper-evident audit ledger",
		use: "Prove after the fact that your record was not altered: every gateway-proxied call and policy verdict is appended to a per-workspace hash chain, so a later deletion, insertion, reorder or edit is detectable by anyone holding an export.",
		type: "trust",
		state: "shipped",
		doc: "/audit-ledger",
	},
	{
		date: "2026-05-02",
		title: "OpenTelemetry-native capture",
		use: "Take your traces elsewhere whenever you want — spans are written in the OpenTelemetry GenAI conventions rather than a private schema.",
		type: "observability",
		state: "shipped",
		doc: "/concepts",
	},
	{
		date: "2026-05-02",
		title: "EU AI Act Article 12 export",
		use: "Export the record-keeping pack Article 12 asks for, mapped obligation by obligation, and hand it to whoever has to check it.",
		type: "trust",
		state: "shipped",
	},
	{
		date: "2026-05-02",
		title: "Apache 2.0, no relicensing",
		use: "Self-host it, fork it, or run the hosted version — the whole project is Apache 2.0 with a written no-relicensing pledge and no separate enterprise tree.",
		type: "platform",
		state: "shipped",
	},
];

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * CADENCE — one bar per month, DERIVED, never written down
 * ─────────────────────────────────────────────────────────────────────────────
 * A count that is computed from the rows it counts cannot disagree with them.
 * That is the entire reason this is a reduce and not a literal: this repo has
 * shipped a hand-written count that drifted from its source and leaked into
 * published copy (`scripts/ci/check-provider-count.py`'s own docstring, B-068).
 */
export type CadenceBar = { month: string; label: string; count: number };

export const CADENCE: CadenceBar[] = (() => {
	const byMonth = new Map<string, number>();
	for (const e of ENTRIES) {
		const m = e.date.slice(0, 7);
		byMonth.set(m, (byMonth.get(m) ?? 0) + 1);
	}
	const fmt = new Intl.DateTimeFormat("en", { month: "short" });
	return [...byMonth.entries()]
		.sort(([a], [b]) => a.localeCompare(b))
		.map(([month, count]) => ({
			month,
			label: fmt.format(new Date(`${month}-01T00:00:00Z`)),
			count,
		}));
})();

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * HERO STAT CARDS
 * ─────────────────────────────────────────────────────────────────────────────
 * Five numbers. `source` is RENDERED under each card, not kept in a comment — a
 * number on a marketing page without its provenance is how this repo has
 * shipped a wrong count before.
 *
 * `value` is a string on purpose. One is hedged ("150+") and one is a triple
 * ("2 / 4 / 5"); typing them as numbers invites a future edit that un-hedges a
 * claim the provider-count guard then refuses.
 *
 * Rejected candidates, and why each was refused, are in `stats-rationale.md`.
 */
export type Stat = {
	value: string;
	unit?: string;
	label: string;
	/** Rendered under the card. Names where the number came from, in the customer's terms. */
	source: string;
};

export const STATS: Stat[] = [
	{
		// Derived, not typed. See CADENCE's note.
		value: String(ENTRIES.length),
		label: "changes shipped",
		source: "every entry below, May 2026 to today",
	},
	{
		value: String(CADENCE.length),
		unit: "months",
		label: "of continuous shipping",
		source: `${CADENCE[0]?.label ?? ""} to ${CADENCE[CADENCE.length - 1]?.label ?? ""} 2026`,
	},
	{
		value: "2 / 4 / 5",
		unit: "ms",
		label: "gateway overhead, p50 / p95 / p99",
		source: "AIGatewayBench, 2026-09-07, two runs on a 4-vCPU host",
	},
	{
		value: "14",
		unit: "MB",
		label: "peak memory in that run",
		source: "same run; the next-lightest gateway measured 101 MB",
	},
	{
		value: "150+",
		label: "providers, one endpoint",
		source:
			"the compiled provider catalogue, held equal to this claim by a repo check",
	},
];

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT'S NEXT — a PUBLIC subset, authored here, exported from nothing
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * `docs/runbook/ROADMAP.md` is `classification: RESTRICTED` (its own line 1).
 * NOTHING from it is quoted, closely paraphrased, or linked. These five themes
 * were written from scratch after reading it, and each was checked against
 * three rules before it survived:
 *
 *   1. NO DATES, no order, no sprint, no "next up". A theme is a direction, and
 *      a direction cannot slip.
 *   2. NO INTERNAL REASONING. If the only honest way to state an item was to
 *      explain why it is not built or what it is blocked on, it was dropped
 *      rather than softened.
 *   3. NOTHING from the roadmap's cut, deferred, first-paying-user or
 *      at-1000-users sections; no ticket id of any kind; no reliability or
 *      audit-register item; no competitor named; no revenue or customer count.
 *
 * Each is a capability a customer would ask for by name, stated as a thing they
 * will be able to do. None carries a date, and the band above it says so.
 */
export type Next = { theme: string; blurb: string };

export const NEXT: Next[] = [
	{
		theme: "Every setting on the span",
		blurb:
			'Temperature, top-p, token limits, the tool list and the exact deployment the call reached — recorded and filterable, so "what were we actually running" is a query.',
	},
	{
		theme: "Tool calls in full",
		blurb:
			"Per-call arguments, result, status and latency on the trace page where you capture content, and name, status, latency and sizes where you do not — rather than a count standing in for detail.",
	},
	{
		theme: "Who started this run",
		blurb:
			"A human identity on sessions and traces, so an investigation can answer who initiated a run and not only which session it belonged to.",
	},
	{
		theme: "More ways to cut the list",
		blurb:
			"Grouping and sorting by the dimensions that matter when something is wrong — agent, tool, error type, cost — beyond the handful available today.",
	},
	{
		theme: "Exports without a ceiling",
		blurb:
			"A large export that continues past the current row cap instead of stopping at it, so an export of a big run is the whole run.",
	},
];
