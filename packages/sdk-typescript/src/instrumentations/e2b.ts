/**
 * E2B instrumentation for Tracelane.
 *
 * Wraps E2B Sandbox.create() to emit OTel spans for sandbox lifecycle events.
 * Un-killed sandboxes are one of the top AI cost overrun causes — these spans
 * let operators attribute sandbox costs to specific agent runs and detect
 * runaway sandbox creation patterns.
 *
 * @example
 * ```ts
 * import { Sandbox } from "e2b";
 * import { instrumentE2B } from "@tracelanedev/sdk/e2b";
 *
 * instrumentE2B(Sandbox);
 * const sandbox = await Sandbox.create({ template: "base" });
 * // Span emitted for create(), kill() patched on the resulting instance
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-e2b", "0.1.0");

interface SandboxClassLike {
	create: (...args: unknown[]) => Promise<unknown>;
}

/**
 * Instrument an E2B Sandbox class to emit OTel spans.
 *
 * @param sandboxClass - An E2B Sandbox class (e.g. Sandbox, CodeInterpreter)
 */
export function instrumentE2B(sandboxClass: SandboxClassLike): void {
	_patchCreate(sandboxClass);
}

function _patchCreate(sandboxClass: SandboxClassLike): void {
	const originalCreate = sandboxClass.create.bind(sandboxClass);

	sandboxClass.create = async (...args: unknown[]) => {
		const opts = args[0] as Record<string, unknown> | undefined;
		const template = String(opts?.template ?? "unknown");
		const timeout = Number(opts?.timeout ?? 300);

		return tracer.startActiveSpan(
			"e2b.sandbox.create",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "e2b",
					"e2b.template": template,
					"e2b.timeout_s": timeout,
					"e2b.operation": "create",
				},
			},
			async (span) => {
				try {
					const start = Date.now();
					const sandbox = (await originalCreate(...args)) as Record<
						string,
						unknown
					>;
					const durationMs = Date.now() - start;
					span.setAttribute("e2b.create_duration_ms", durationMs);

					const sandboxId = sandbox.sandboxId ?? sandbox.id;
					if (typeof sandboxId === "string") {
						span.setAttribute("e2b.sandbox_id", sandboxId);
					}

					// Patch kill() on the resulting sandbox instance
					_patchKillInstance(
						sandbox,
						typeof sandboxId === "string" ? sandboxId : "",
					);

					span.setStatus({ code: SpanStatusCode.OK });
					return sandbox;
				} catch (e) {
					span.recordException(e as Error);
					span.setStatus({ code: SpanStatusCode.ERROR, message: String(e) });
					throw e;
				} finally {
					span.end();
				}
			},
		);
	};
}

function _patchKillInstance(
	sandbox: Record<string, unknown>,
	sandboxId: string,
): void {
	for (const methodName of ["kill", "close"]) {
		const original = sandbox[methodName];
		if (typeof original !== "function") continue;
		const originalBound = (
			original as (...args: unknown[]) => Promise<unknown>
		).bind(sandbox);

		sandbox[methodName] = async (...args: unknown[]) => {
			return tracer.startActiveSpan(
				`e2b.sandbox.${methodName}`,
				{
					kind: SpanKind.CLIENT,
					attributes: {
						"gen_ai.provider.name": "e2b",
						"e2b.sandbox_id": sandboxId,
						"e2b.operation": methodName,
					},
				},
				async (span) => {
					try {
						const result = await originalBound(...args);
						span.setStatus({ code: SpanStatusCode.OK });
						return result;
					} catch (e) {
						span.recordException(e as Error);
						span.setStatus({ code: SpanStatusCode.ERROR, message: String(e) });
						throw e;
					} finally {
						span.end();
					}
				},
			);
		};
	}
}
