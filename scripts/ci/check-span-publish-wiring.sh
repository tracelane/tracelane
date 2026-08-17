#!/usr/bin/env bash
# scripts/ci/check-span-publish-wiring.sh
#
# CI guard for  / (silent 100% span-drop in prod).
#
# The gateway publishes every span to NATS. When `NATS_URL` is absent from the
# gateway *container env*, `AppState::nats` is `None` and the per-request publish
# is skipped — historically with no error and no log, so `/v1/chat/completions`
# returned 200 while ClickHouse `tracelane.spans` stayed at 0 rows. The code path
# is now loud (crates/gateway/src/otlp_emit.rs::note_span_dropped_no_nats), but
# the durable fix is to keep the prod gateway *wired* to NATS. This guard pins
# that wiring so a future compose edit can't silently reintroduce the regression.
#
# Asserts: the `gateway` service in infra/prod/docker-compose.yml carries NATS_URL
# literally in the COMMITTED compose (its `environment:` block). We deliberately do
# NOT accept "it's in the env_file" as sufficient: env_file targets (.env) are
# gitignored and uncommitted, so this guard cannot see them — a future edit moving
# NATS_URL into .env would let the guard pass while a later .env edit silently drops
# it and reintroduces the 100% span-loss regression. Keeping the value in the
# committed, reviewable compose is the durable guarantee this guard enforces.
#
# Falsify it: ./scripts/ci/check-span-publish-wiring.sh --selftest
set -euo pipefail

COMPOSE="infra/prod/docker-compose.yml"

# check_compose <compose-file> — 0 if that file's `gateway` service wires
# NATS_URL, 1 (with the reason on stdout) otherwise.
#
# The check is SERVICE-SCOPED, not file-scoped: NATS_URL under `ingest:` says
# nothing about the gateway, and it is the gateway's publish that dies. The
# selftest pins that distinction (`nats_under_OTHER_service_only`) because a
# whole-file `grep NATS_URL` would pass the exact compose that caused the
# incident.
check_compose() {
	local compose="$1" gateway_block

	if [ ! -f "$compose" ]; then
		echo "FAIL: $compose not found ( wiring guard cannot verify)"
		return 1
	fi

	# Slice the gateway service block: from the `  gateway:` key to the next
	# top-level (2-space-indented) service key. Then assert NATS_URL appears in it.
	gateway_block="$(awk '
	  /^  gateway:/        { in_gw = 1; next }
	  in_gw && /^  [A-Za-z0-9_-]+:/ { in_gw = 0 }
	  in_gw                { print }
	' "$compose")"

	if [ -z "$gateway_block" ]; then
		echo "FAIL: could not locate the 'gateway:' service block in $compose"
		return 1
	fi

	if ! grep -q 'NATS_URL' <<<"$gateway_block"; then
		echo "FAIL: $compose 'gateway' service is missing NATS_URL."
		echo "      Without it, span publish silently disables in prod and 100% of"
		echo "      spans are dropped ( / ). Add to the gateway service"
		echo "      'environment:' block, e.g.:  NATS_URL: nats://nats:4222"
		return 1
	fi

	echo "OK: prod 'gateway' service wires NATS_URL ($compose) —  guard passed"
	return 0
}

# Plant the compose that caused the incident and prove this guard blocks it —
# and prove a correctly-wired compose still passes, so the guard cannot be
# "correct" by refusing everything.
selftest() {
	local fails=0 out rc
	local before after
	before="$(git status --porcelain 2>/dev/null || true)"
	# NOT `local`: the EXIT trap runs after this frame is gone, and a `local`
	# would make cleanup die on `unbound variable` and clobber the exit code.
	SELFTEST_TMP="$(mktemp -d)"
	local tmp="$SELFTEST_TMP"
	trap 'rm -rf "$SELFTEST_TMP"' EXIT

	# Correctly wired — mapping form, mirrors the real prod compose.
	cat >"$tmp/good.yml" <<'YML'
services:
  gateway:
    image: tracelane/gateway:local
    environment:
      CLICKHOUSE_URL: http://clickhouse:8123
      NATS_URL: nats://nats:4222
    networks: [tracelane]

  ingest:
    image: tracelane/ingest:local
YML

	# Correctly wired — `- KEY=value` list form is equally valid compose.
	cat >"$tmp/good-list.yml" <<'YML'
services:
  gateway:
    image: tracelane/gateway:local
    environment:
      - CLICKHOUSE_URL=http://clickhouse:8123
      - NATS_URL=nats://nats:4222

  ingest:
    image: tracelane/ingest:local
YML

	# THE INCIDENT SHAPE: gateway relegates NATS_URL to the gitignored env_file.
	cat >"$tmp/env-file-only.yml" <<'YML'
services:
  gateway:
    image: tracelane/gateway:local
    env_file: [./.env]
    environment:
      CLICKHOUSE_URL: http://clickhouse:8123

  ingest:
    image: tracelane/ingest:local
YML

	# The case a whole-file grep would wave through: NATS_URL present, but only
	# under a DIFFERENT service.
	cat >"$tmp/other-service-only.yml" <<'YML'
services:
  gateway:
    image: tracelane/gateway:local
    environment:
      CLICKHOUSE_URL: http://clickhouse:8123

  ingest:
    image: tracelane/ingest:local
    environment:
      NATS_URL: nats://nats:4222
YML

	# No gateway service at all (e.g. renamed) — must not silently pass.
	cat >"$tmp/no-gateway.yml" <<'YML'
services:
  ingest:
    image: tracelane/ingest:local
    environment:
      NATS_URL: nats://nats:4222
YML

	_case() { # name, compose-path, expect_rc, expect_substring
		out="$(check_compose "$2" 2>&1)" && rc=0 || rc=$?
		if [ "$rc" -ne "$3" ]; then
			echo "  ✗ $1 — expected rc=$3 got rc=$rc: $out"
			fails=$((fails + 1))
			return 0
		fi
		if [ -n "${4:-}" ] && ! grep -q "$4" <<<"$out"; then
			echo "  ✗ $1 — rc correct but output never said '$4': $out"
			fails=$((fails + 1))
			return 0
		fi
		echo "  ✓ $1 (rc=$rc)"
	}

	_case "wired_gateway_PASSES"          "$tmp/good.yml"               0 "guard passed"
	_case "wired_gateway_listform_PASSES" "$tmp/good-list.yml"          0 "guard passed"
	_case "env_file_only_BLOCKS"          "$tmp/env-file-only.yml"      1 "missing NATS_URL"
	_case "nats_under_OTHER_service_only" "$tmp/other-service-only.yml" 1 "missing NATS_URL"
	_case "no_gateway_service_BLOCKS"     "$tmp/no-gateway.yml"         1 "could not locate"
	_case "missing_compose_BLOCKS"        "$tmp/does-not-exist.yml"     1 "not found"

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
	echo "  (no args)   assert $COMPOSE wires NATS_URL into the gateway service" >&2
	echo "  --selftest  plant an unwired compose and prove this guard blocks it" >&2
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

check_compose "$COMPOSE"
