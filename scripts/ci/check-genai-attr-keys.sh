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
# Falsify it:                   ./scripts/ci/check-genai-attr-keys.sh --selftest
set -euo pipefail

# The two patterns ARE the guard. Kept as variables so `--selftest` exercises
# the same strings CI does — a selftest that re-types the pattern proves only
# that the copy works.
LLM_EXTRACT="JSONExtract(String|Int)\(.*'llm\.(model_name|provider|usage\.)"
GENAI_PRIMARY="'gen_ai_(response_model|request_model|provider_name|system|usage_input_tokens|usage_output_tokens)'"

# scan_root <dir> — 0 if every *.sql under <dir> is clean, 1 if any has drifted.
# PER FILE, deliberately: a canonical file sitting beside a drifted one does not
# launder it (selftest case `drifted_beside_canonical` pins that).
scan_root() {
	local root="$1" fail=0 f
	while IFS= read -r f; do
		if grep -qE "$LLM_EXTRACT" "$f"; then
			if ! grep -qE "$GENAI_PRIMARY" "$f"; then
				echo "FAIL: $f"
				echo "  extracts OpenInference 'llm.*' GenAI attributes without the canonical"
				echo "  'gen_ai_*' primary (ADR-043 / ). The Model column + SLO panel ship"
				echo "  empty. Read gen_ai_* with coalesce() fallbacks to dotted + llm.* — see"
				echo "  infra/dev/clickhouse/migrations/06_genai_attr_keys_and_slo.sql."
				fail=1
			fi
		fi
	done < <(find "$root" -name '*.sql' 2>/dev/null | sort)
	return "$fail"
}

# Plant the drift the guard exists to catch, prove it BLOCKS, and prove the
# canonical form does NOT — a guard that fails on everything looks identical to
# a working one until the day it blocks a correct change.
selftest() {
	local fails=0 out rc before after
	before="$(git status --porcelain 2>/dev/null || true)"
	# NOT `local` — the EXIT trap runs after this frame is gone, and a `local`
	# here makes the cleanup die on `unbound variable` and overwrite the exit
	# code with 1 (observed: "selftest PASSED." followed by EXIT=1).
	SELFTEST_TMP="$(mktemp -d)"
	local tmp="$SELFTEST_TMP"
	trap 'rm -rf "$SELFTEST_TMP"' EXIT

	# The drift state: `llm.*` extraction with no gen_ai_* primary anywhere.
	mkdir -p "$tmp/bad"
	cat >"$tmp/bad/mv_drifted.sql" <<'SQL'
CREATE MATERIALIZED VIEW mv_trace_summaries AS
SELECT JSONExtractString(attributes, 'llm.model_name') AS model,
       JSONExtractInt(attributes, 'llm.usage.prompt_tokens') AS input_tokens
FROM tracelane.spans;
SQL

	# The canonical form: gen_ai_* primary, llm.* only as the final coalesce arm.
	mkdir -p "$tmp/good"
	cat >"$tmp/good/mv_canonical.sql" <<'SQL'
CREATE MATERIALIZED VIEW mv_trace_summaries AS
SELECT coalesce(
         JSONExtractString(attributes, 'gen_ai_response_model'),
         JSONExtractString(attributes, 'llm.model_name')
       ) AS model
FROM tracelane.spans;
SQL
	# A file with no GenAI extraction at all must never be flagged.
	cat >"$tmp/good/unrelated.sql" <<'SQL'
CREATE TABLE tracelane.audit_log (seq UInt64, tenant_id UUID) ENGINE = MergeTree ORDER BY seq;
SQL

	# Drift + canonical in the SAME tree: still a failure, named per file.
	mkdir -p "$tmp/both"
	cp "$tmp/bad/mv_drifted.sql" "$tmp/good/mv_canonical.sql" "$tmp/both/"

	_case() { # name, dir, expect_rc, expect_substring_in_output
		out="$(scan_root "$2" 2>&1)" && rc=0 || rc=$?
		if [ "$rc" -ne "$3" ]; then
			echo "  ✗ $1 — expected rc=$3 got rc=$rc: $out"
			fails=$((fails + 1))
			return 0
		fi
		if [ -n "${4:-}" ] && ! grep -q "$4" <<<"$out"; then
			echo "  ✗ $1 — rc correct but output never named '$4': $out"
			fails=$((fails + 1))
			return 0
		fi
		echo "  ✓ $1 (rc=$rc)"
	}

	_case "drifted_llm_only_BLOCKS"      "$tmp/bad"  1 "mv_drifted.sql"
	_case "canonical_coalesce_PASSES"    "$tmp/good" 0 ""
	_case "drifted_beside_canonical"     "$tmp/both" 1 "mv_drifted.sql"
	# The negative that stops the whole guard going vacuous: the clean tree must
	# never report the canonical file.
	out="$(scan_root "$tmp/both" 2>&1)" && rc=0 || rc=$?
	if grep -q "mv_canonical.sql" <<<"$out"; then
		echo "  ✗ canonical_not_false_flagged — the canonical file was reported"
		fails=$((fails + 1))
	else
		echo "  ✓ canonical_not_false_flagged"
	fi

	after="$(git status --porcelain 2>/dev/null || true)"
	if [ "$before" != "$after" ]; then
		echo "  ✗ tree_restored — selftest left the working tree modified"
		fails=$((fails + 1))
	else
		echo "  ✓ tree_restored (git status unchanged)"
	fi

	if [ "$fails" -gt 0 ]; then
		echo "selftest FAILED — $fails case(s). This guard is not trustworthy."
		return 1
	fi
	echo "selftest PASSED."
	return 0
}

usage() {
	echo "usage: $(basename "$0") [--selftest]" >&2
	echo "  (no args)   scan infra/**/*.sql for the ADR-043 gen_ai_* drift" >&2
	echo "  --selftest  plant the drift and prove this guard blocks it" >&2
}

if [ "$#" -gt 1 ]; then
	echo "error: unexpected extra arguments: ${*:2}" >&2
	usage
	exit 2
fi
case "${1:-}" in
	"") ;;
	--selftest)
		selftest
		exit $?
		;;
	*)
		echo "error: unknown argument: $1" >&2
		usage
		exit 2
		;;
esac

if ! scan_root infra; then
	exit 1
fi

echo "check-genai-attr-keys: OK — GenAI-attr SQL reads the canonical gen_ai_* keys."
