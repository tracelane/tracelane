import { renderToStaticMarkup } from "react-dom/server";
import { expect, it, vi } from "vitest";
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));
import { SessionRow } from "@/components/sessions/SessionRow";
import { SwimlaneView } from "@/components/trace-viewer/SwimlaneView";
import { TraceList } from "@/components/trace-viewer/TraceList";
import { TraceSummaryHeader } from "@/components/trace-viewer/TraceSummaryHeader";
import { computeLanes } from "@/lib/trace/lanes";
const span = {
	span_id: "a",
	parent_span_id: null,
	name: "chat",
	start_time: "2026-09-24T00:00:00Z",
	end_time: "2026-09-24T00:00:01Z",
	duration_us: 1000000,
	status_code: 1,
	status_message: "",
	aft_ids: [],
	intervention: 0,
	attributes: JSON.stringify({
		gen_ai_agent_name: "claude-code",
		gen_ai_request_model: "vertex/claude-haiku-4-5-20251001",
		gen_ai_operation_name: "chat",
	}),
};
it("trace list model opens the normalized model profile", () => {
	const html = renderToStaticMarkup(
		<TraceList
			traces={[
				{
					trace_id: "trace",
					loop_calls: 4,
					loops_available: true,
					rescued: "failover",
					rescues_available: true,
					root_name: "chat",
					start_time: span.start_time,
					duration_us: 1000000,
					span_count: 1,
					error_count: 0,
					intervention: 0,
					model: "vertex/claude-haiku-4-5-20251001",
					cost_usd: 0,
					total_tokens: 0,
				},
			]}
		/>,
	);
	expect(html).toContain('href="/agents/model/claude-haiku-4-5"');
	expect(html).toContain("Repeated tool call ×4");
	expect(html).toContain("Rescued by failover");
});
it("trace header links the observed agent and model", () => {
	const html = renderToStaticMarkup(<TraceSummaryHeader spans={[span]} />);
	expect(html).toContain('href="/agents/agent/claude-code"');
	expect(html).toContain('href="/agents/model/claude-haiku-4-5"');
});
it("lane headers link the observed agent without guessing from the lane label", () => {
	const html = renderToStaticMarkup(
		<SwimlaneView
			lanes={computeLanes([span])}
			startUs={0}
			totalUs={1000000}
			onSelectSpan={() => {}}
		/>,
	);
	expect(html).toContain('href="/agents/agent/claude-code"');
});
it("session agent chip opens the profile and keeps the session link", () => {
	const html = renderToStaticMarkup(
		<SessionRow
			s={{
				session_id: "session",
				loop_calls: 3,
				loops_available: true,
				agent_name: "codex",
				turns: 1,
				started_at: span.start_time,
				last_activity: span.end_time,
				duration_us: 1000000,
				error_count: 0,
				status: "ok",
				cost_usd: 0,
				total_tokens: 0,
				model: "",
			}}
			win={null}
		/>,
	);
	expect(html).toContain('href="/agents/agent/codex"');
	expect(html).toContain('href="/sessions/session"');
	expect(html).toContain("Repeated tool call ×3");
});
