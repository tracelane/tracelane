#!/usr/bin/env bash
# CI guard (ADR-043 / ): ClickHouse SQL that extracts GenAI model /
# provider / token attributes MUST read the canonical flattened `gen_ai_*` keys
# — the form the gateway actually writes — not bare OpenInference `llm.*`. When
# an MV reads only `llm.*`, the dashboard Traces "Model" column and the SLO
# panel ship EMPTY (the original ADR-043 bug; the self-host mirrors carried the
# stale keys → ).
#
# `llm.*` is allowed ONLY as the final fallback inside a coalesce(). This guard
# enforces that structurally without parsing SQL: any file that references an
# `llm.{model_name,provider,usage.*}` extraction MUST also reference a
# `gen_ai_*` primary key. A file with `llm.*` but no `gen_ai_*` is the drift
# state and fails.
#
# Same class as ADR-040 (two schema sources diverging until something reads
# across the seam). Run locally: ./scripts/ci/check-genai-attr-keys.sh
set -euo pipefail

FAIL=0

while IFS= read -r f; do
	if grep -qE "JSONExtract(String|Int)\(.*'llm\.(model_name|provider|usage\.)" "$f"; then
		if ! grep -qE "'gen_ai_(response_model|request_model|provider_name|system|usage_input_tokens|usage_output_tokens)'" "$f"; then
			echo "FAIL: $f"
			echo "  extracts OpenInference 'llm.*' GenAI attributes without the canonical"
			echo "  'gen_ai_*' primary (ADR-043 / ). The Model column + SLO panel ship"
			echo "  empty. Read gen_ai_* with coalesce() fallbacks to dotted + llm.* — see"
			echo "  infra/dev/clickhouse/migrations/06_genai_attr_keys_and_slo.sql."
			FAIL=1
		fi
	fi
done < <(find infra -name '*.sql' 2>/dev/null | sort)

if [[ "$FAIL" -eq 1 ]]; then
	exit 1
fi

echo "check-genai-attr-keys: OK — GenAI-attr SQL reads the canonical gen_ai_* keys."
