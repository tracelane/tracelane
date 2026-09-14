#!/usr/bin/env bash
# PLT-23 — Tracelane inside AIGatewayBench, the OpenAI-route overhead scenario.
#
# Drives the LiteLLM-post methodology (github.com/BerriAI/ai-gateway-bench,
# pinned commit ff372fc, MIT) against every gateway on the SAME route
# (`/v1/chat/completions`, OpenAI-shaped body) and the SAME deterministic mock
# (crates/mock-upstream), because Tracelane has no `/v1/messages` route
# (specs/PLT-23-gateway-overhead-benchmark.md §1). See README.md in this
# directory for the full design and per-gateway notes.
#
# Usage:
#   bash run.sh [run-label]      # run-label disambiguates two same-day runs;
#                                 # defaults to "1". Writes
#                                 # results/<date>-<host-label>-run<label>.csv
#
# Env overrides (all optional):
#   GWBENCH_HARNESS_DIR   default $HOME/.cache/tracelane/aigatewaybench-src
#   GWBENCH_VENV_DIR      default $HOME/.cache/tracelane/aigatewaybench-venv
#   GWBENCH_HOST_LABEL    default "dev-wsl2" — stamped into the CSV filename
#                         and the "not publishable" note in RESULTS.md
#   MOCK_URL              default "http://127.0.0.1:9000" — the ONE address
#                         every gateway (including the direct baseline AND
#                         Tracelane's ANTHROPIC_BASE_URL) is pointed at.
#                         On THIS dev box it must be overridden to a port
#                         other than 9000 (ClickHouse's native TCP port also
#                         binds 9000 under `network_mode: host` — see
#                         tracelane.compose.yml). On a CCX23 (or any box
#                         without that collision) the mock's public IPv4
#                         clears Tracelane's own SSRF guard (loopback/RFC1918
#                         are blocked; a real public IP is not) — see the
#                         "why Tracelane needs this" note below §1.
#   MOCK_BIND             default "127.0.0.1" — the mock's own listen address.
#                         Set to 0.0.0.0 on a box being addressed by its
#                         public IP so external gateways (and, on a CCX23,
#                         Tracelane itself) can reach it.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"

HARNESS_COMMIT="ff372fc"
HARNESS_REPO="https://github.com/BerriAI/ai-gateway-bench.git"
HARNESS_DIR="${GWBENCH_HARNESS_DIR:-$HOME/.cache/tracelane/aigatewaybench-src}"
VENV_DIR="${GWBENCH_VENV_DIR:-$HOME/.cache/tracelane/aigatewaybench-venv}"
HOST_LABEL="${GWBENCH_HOST_LABEL:-dev-wsl2}"
RUN_LABEL="${1:-1}"

RESULTS_DIR="$HERE/results"
mkdir -p "$RESULTS_DIR"
RUN_DATE="$(date -u +%Y-%m-%d)"
OUT_CSV="$RESULTS_DIR/${RUN_DATE}-${HOST_LABEL}-run${RUN_LABEL}.csv"
WORK_DIR="$(mktemp -d /tmp/gwbench-run.XXXXXX)"

# 9100, not 9000: the Tracelane compose stack runs ClickHouse on the host network and 9000 is
# its native-protocol port — the first CCX23 run (2026-09-06) put the mock on 9000 and
# ClickHouse exited 102 on bind. Every gateway takes its upstream from MOCK_URL, nothing else moves.
MOCK_URL="${MOCK_URL:-http://127.0.0.1:9100}"
MOCK_BIND="${MOCK_BIND:-127.0.0.1}"
MOCK_PORT="$(printf '%s' "$MOCK_URL" | sed -E 's#^https?://[^:/]+:([0-9]+)/?$#\1#')"
if ! [[ "$MOCK_PORT" =~ ^[0-9]+$ ]]; then
    echo "REFUSING: could not parse a port out of MOCK_URL=$MOCK_URL (expected http://host:port)" >&2
    exit 1
fi
GATEWAY_PORT=8080
LITELLM_PORT=8102
BIFROST_PORT=8103
PORTKEY_PORT=8787
CLICKHOUSE_PASSWORD="tracelane_bench"
COMPOSE_PROJECT="tlbench-plt23"

PIDS_TO_KILL=()
COMPOSE_UP=0

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

cleanup() {
    log "cleaning up"
    for pid in "${PIDS_TO_KILL[@]:-}"; do
        [ -n "$pid" ] && kill -9 "$pid" >/dev/null 2>&1 || true
    done
    if [ "$COMPOSE_UP" = "1" ]; then
        docker compose -f "$HERE/tracelane.compose.yml" -p "$COMPOSE_PROJECT" down -v --remove-orphans >/dev/null 2>&1 || true
    fi
    pkill -9 -f "litellm --config $WORK_DIR" >/dev/null 2>&1 || true
    # Bifrost's actual server binary is a GRANDCHILD of the `npx` process we
    # tracked (npx -> node -> a separately downloaded `bifrost-http-0`), so
    # killing the tracked PID alone leaves it running — matched here by name
    # instead of via the (never-tracked) grandchild PID. Found 2026-09-06: it
    # survived both dev runs as an orphan once the pattern below was missing
    # the "-http-0" the real binary is actually named.
    pkill -9 -f "bifrost-http-0 --app-dir $WORK_DIR" >/dev/null 2>&1 || true
    pkill -9 -f "@portkey-ai/gateway" >/dev/null 2>&1 || true
    # mock-upstream: `cargo run` does not always exec-replace into the built
    # binary, so the tracked PID can be `cargo` itself rather than the server.
    # -x matches the process NAME exactly (not a cmdline substring), which is
    # safe here because run.sh runs one gateway at a time (not two overlapping
    # invocations sharing a box).
    pkill -9 -x mock-upstream >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_http() {
    # wait_http <url> <timeout-seconds>
    local url="$1" timeout="${2:-60}" waited=0
    while [ "$waited" -lt "$timeout" ]; do
        if curl -fsS -m 2 -o /dev/null "$url" 2>/dev/null; then
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done
    return 1
}

wait_port() {
    # wait_port <host> <port> <timeout-seconds> — a bare TCP connect, not an
    # HTTP status check, because litellm/portkey/bifrost each expose a
    # different (or no) health path; the thing we actually depend on is "the
    # socket accepts a connection", proven separately per-gateway below by an
    # actual /v1/chat/completions round trip before any scenario runs.
    local host="$1" port="$2" timeout="${3:-60}" waited=0
    while [ "$waited" -lt "$timeout" ]; do
        if (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null; then
            exec 3>&- 3<&- 2>/dev/null || true
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done
    return 1
}

# ── 0. pin + prerequisites ──────────────────────────────────────────────────

if [ ! -d "$HARNESS_DIR/.git" ]; then
    log "cloning AIGatewayBench harness -> $HARNESS_DIR"
    mkdir -p "$(dirname "$HARNESS_DIR")"
    git clone "$HARNESS_REPO" "$HARNESS_DIR" >&2
fi
git -C "$HARNESS_DIR" fetch --quiet origin "$HARNESS_COMMIT" 2>/dev/null || true
git -C "$HARNESS_DIR" checkout --quiet "$HARNESS_COMMIT"
# Apply our harness patches on top of the pinned commit (idempotent: skip one that is already
# in). 0002 makes "zero injected pacing" actually zero in the mock — without it every STREAMING
# gateway pays ~1.25 ms per chunk of tokio timer tick that the non-streaming path never pays
# (measured 2026-09-06: 51–56 ms → ~1 ms for 40 chunks). Same patches ship upstream from upstream/.
for patch in "$HERE"/upstream/000[2-9]-*.patch; do
    [ -f "$patch" ] || continue
    if git -C "$HARNESS_DIR" apply --check "$patch" >/dev/null 2>&1; then
        git -C "$HARNESS_DIR" apply "$patch" && log "applied harness patch $(basename "$patch")"
    elif git -C "$HARNESS_DIR" apply --check --reverse "$patch" >/dev/null 2>&1; then
        log "harness patch $(basename "$patch") already applied"
    else
        log "REFUSING: harness patch $(basename "$patch") does not apply to $HARNESS_COMMIT"; exit 1
    fi
done
HARNESS_ACTUAL_COMMIT="$(git -C "$HARNESS_DIR" rev-parse --short=7 HEAD)"
if [ "$HARNESS_ACTUAL_COMMIT" != "$HARNESS_COMMIT" ]; then
    log "REFUSING: harness at $HARNESS_ACTUAL_COMMIT, pinned commit is $HARNESS_COMMIT"
    exit 1
fi
log "harness pinned at $HARNESS_ACTUAL_COMMIT"

# `uv` when present (fast), plain `python3 -m venv` + pip otherwise — the first CCX23 run
# (2026-09-06) had no uv and every gateway row went CANNOT DETERMINE on "locust: not found".
pip_install() {
    if command -v uv >/dev/null 2>&1; then uv pip install --python "$VENV_DIR/bin/python" "$@" >&2
    else "$VENV_DIR/bin/python" -m pip install --quiet "$@" >&2; fi
}
if [ ! -x "$VENV_DIR/bin/locust" ]; then
    log "building bench venv -> $VENV_DIR"
    if command -v uv >/dev/null 2>&1; then uv venv "$VENV_DIR" >&2; else python3 -m venv "$VENV_DIR" >&2; fi
    pip_install -r "$HARNESS_DIR/requirements.txt"
    [ -x "$VENV_DIR/bin/locust" ] || { log "REFUSING: locust did not install into $VENV_DIR"; exit 1; }
fi
if ! "$VENV_DIR/bin/python" -c "import litellm" >/dev/null 2>&1; then
    log "installing litellm[proxy] into bench venv"
    pip_install "litellm[proxy]"
fi
LITELLM_VERSION="$("$VENV_DIR/bin/python" -c "import importlib.metadata as m; print(m.version('litellm'))" 2>/dev/null || echo unknown)"

# copy our scenario into the pinned harness tree (this file is also the
# upstream-contribution source under upstream/)
mkdir -p "$HARNESS_DIR/scenarios/openai_overhead"
cp "$HERE/scenarios/openai_overhead/locustfile.py" "$HARNESS_DIR/scenarios/openai_overhead/locustfile.py"

LOAD_1M="$(awk '{print $1}' /proc/loadavg)"
NPROC="$(nproc)"
FREE_G="$(free -g | awk '/^Mem:/{print $2}')"
KERNEL="$(uname -r)"
# A remote bench host receives the tree as a tarball without `.git` (441 MB is not worth
# shipping for one string), so the provisioning script passes the SHA it tarred — suffixed
# `-wip` when the tree had uncommitted changes — and the git read is the local default.
TRACELANE_SHA="${TRACELANE_SHA:-$(git -C "$REPO_ROOT" rev-parse --short=8 HEAD)}"

log "host: ${NPROC} vCPU / ${FREE_G} GB, kernel ${KERNEL}, load1m=${LOAD_1M}"
LOAD_NOTE=""
if awk -v l="$LOAD_1M" 'BEGIN{exit !(l>=4)}'; then
    LOAD_NOTE=" -- WARNING: load1m=${LOAD_1M} >= 4 at run start, per CLAUDE.md \"another agent may be compiling\""
    log "$LOAD_NOTE"
fi

# ── 1. mock upstream ─────────────────────────────────────────────────────────

log "building + starting mock-upstream on ${MOCK_BIND}:${MOCK_PORT} (reachable at $MOCK_URL)"
# ZERO injected pacing, on purpose. The mock defaults to TTFT 20 ms + 5 ms per output token
# (40 tokens) on its STREAMING path, and none of that on its non-streaming path. Tracelane's
# Anthropic adapter always streams upstream (a documented Anthropic usage-accounting fix), the
# other gateways forward the client's non-streaming request — so with defaults the CCX23 run of
# 2026-09-06 charged Tracelane ~248 ms of MOCK pacing and nobody else any. LiteLLM's own
# overhead panel states "zero injected latency"; this matches it and removes the asymmetry.
(cd "$HARNESS_DIR" && MOCK_HOST="$MOCK_BIND" MOCK_PORT=$MOCK_PORT MOCK_TTFT_MS="${MOCK_TTFT_MS:-0}" MOCK_ITL_MS="${MOCK_ITL_MS:-0}" cargo run --release -p mock-upstream >"$WORK_DIR/mock.log" 2>&1) &
MOCK_PID=$!
PIDS_TO_KILL+=("$MOCK_PID")
if ! wait_http "$MOCK_URL/health" 180; then
    log "FATAL: mock-upstream never came up"
    cat "$WORK_DIR/mock.log" >&2
    exit 1
fi
log "mock-upstream up"

# ── output CSV header ────────────────────────────────────────────────────────

{
    echo "# PLT-23 gateway-overhead comparison — AIGatewayBench harness commit ${HARNESS_ACTUAL_COMMIT}"
    echo "# date=${RUN_DATE} host_label=${HOST_LABEL} run_label=${RUN_LABEL} nproc=${NPROC} mem_gb=${FREE_G} kernel=${KERNEL} load1m=${LOAD_1M}${LOAD_NOTE}"
    echo "# tracelane_sha=${TRACELANE_SHA} litellm_python_version=${LITELLM_VERSION}"
    echo "# mock_url=${MOCK_URL} mock_bind=${MOCK_BIND} mock_ttft_ms=${MOCK_TTFT_MS:-0} mock_itl_ms=${MOCK_ITL_MS:-0}"
    echo "gateway,status,version,n,p50_ms,p95_ms,p99_ms,peak_rss_mb,notes"
} >"$OUT_CSV"

append_row() {
    # append_row gateway status version n p50 p95 p99 rss notes
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$@" >>"$OUT_CSV"
}

run_scenario() {
    # run_scenario <label> <target_url> <endpoint> <model> <api_key> <pid-for-rss|->
    local label="$1" target="$2" endpoint="$3" model="$4" apikey="$5" rsspid="$6"
    local prefix="$WORK_DIR/${label}_locust"
    local rss_csv="$WORK_DIR/${label}_rss.csv"

    if [ "$rsspid" != "-" ]; then
        "$VENV_DIR/bin/python" "$HARNESS_DIR/tools/mem_sampler.py" "$rsspid" \
            --output "$rss_csv" --interval 0.25 --duration 32 >"$WORK_DIR/${label}_rss.log" 2>&1 &
        local sampler_pid=$!
    fi

    (
        cd "$HARNESS_DIR" &&
        PYTHONPATH="$HARNESS_DIR" \
        GWBENCH_TARGET="$target" GWBENCH_ENDPOINT="$endpoint" GWBENCH_MODEL="$model" GWBENCH_API_KEY="$apikey" \
        GWBENCH_EXTRA_HEADERS="${GWBENCH_EXTRA_HEADERS:-}" \
        "$VENV_DIR/bin/locust" -f scenarios/openai_overhead/locustfile.py \
            --headless -u 16 -r 16 -t 30s \
            --host "$target" \
            --csv "$prefix" --csv-full-history --only-summary \
            >"$WORK_DIR/${label}_locust.log" 2>&1
    )
    local rc=$?

    if [ "$rsspid" != "-" ]; then
        wait "$sampler_pid" 2>/dev/null || true
    fi

    if [ $rc -ne 0 ] && [ ! -f "${prefix}_stats.csv" ]; then
        echo "CANNOT DETERMINE — locust exited $rc, no stats written: $(tail -n5 "$WORK_DIR/${label}_locust.log" | tr '\n' ' ')"
        return 1
    fi

    # locust's _stats.csv: Type,Name,...,50%,66%,75%,80%,90%,95%,98%,99%,99.9%,99.99%,100%
    # A percentile computed over 100% non-2xx responses is "how fast does the
    # gateway fail", not overhead — CLAUDE.md Rule 1 (a 200 is not proof; a 502
    # is not overhead either). Any failure at all downgrades this to CANNOT
    # DETERMINE rather than a fabricated-looking clean number.
    "$VENV_DIR/bin/python" - "$prefix" <<'PYEOF'
import csv
import sys

prefix = sys.argv[1]
with open(f"{prefix}_stats.csv", newline="", encoding="utf-8") as fh:
    rows = list(csv.DictReader(fh))
row = next((r for r in rows if r["Name"] == "Aggregated"), None)
if row is None:
    print("CANNOT DETERMINE — no Aggregated row in locust stats")
    raise SystemExit(1)
n = int(row["Request Count"])
failures = int(row["Failure Count"])
if n == 0:
    print("CANNOT DETERMINE — zero requests completed")
    raise SystemExit(1)
if failures > 0:
    # Name the failure: locust writes <prefix>_failures.csv with one row per distinct
    # error. The first CCX23 run (2026-09-06) said only "see the service log" — on a box
    # that had already been deleted. Carry the top error text into the CSV notes instead.
    top = ""
    try:
        with open(f"{prefix}_failures.csv", newline="", encoding="utf-8") as fh:
            frows = sorted(csv.DictReader(fh), key=lambda r: -int(r.get("Occurrences", "0") or 0))
        if frows:
            top = f" — top error ({frows[0].get('Occurrences')}x): {frows[0].get('Error', '')[:160]}"
    except OSError:
        pass
    print(f"CANNOT DETERMINE — {failures}/{n} requests failed (non-2xx){top}")
    raise SystemExit(1)
p50 = row["50%"]
p95 = row["95%"]
p99 = row["99%"]
print(f"OK {n} {p50} {p95} {p99}")
PYEOF
}

peak_rss_mb() {
    local rss_csv="$1"
    [ -f "$rss_csv" ] || { echo ""; return; }
    "$VENV_DIR/bin/python" - "$rss_csv" <<'PYEOF'
import csv
import sys

path = sys.argv[1]
try:
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
except FileNotFoundError:
    print("")
    raise SystemExit
if not rows:
    print("")
    raise SystemExit
peak = max(int(r["rss_bytes"]) for r in rows)
print(round(peak / 1_000_000, 3))
PYEOF
}

# ── 2. direct-to-mock baseline ───────────────────────────────────────────────

log "running scenario: direct (baseline)"
RESULT="$(run_scenario direct "$MOCK_URL" /v1/chat/completions mock gwbench "$MOCK_PID")"
if [[ "$RESULT" == OK* ]]; then
    read -r _ n p50 p95 p99 <<<"$RESULT"
    RSS="$(peak_rss_mb "$WORK_DIR/direct_rss.csv")"
    append_row direct ok direct-mock "$n" "$p50" "$p95" "$p99" "$RSS" ""
else
    append_row direct "CANNOT_DETERMINE" "" "" "" "" "" "" "${RESULT#CANNOT DETERMINE — }"
fi

# ── 3. Tracelane self-host, capture ON ───────────────────────────────────────

log "starting Tracelane gateway (self-host, capture ON) via docker compose"
TRACELANE_MASTER_KEY="$(openssl rand -base64 32)"
export TRACELANE_MASTER_KEY
export CLICKHOUSE_PASSWORD
export GWBENCH_MOCK_URL="$MOCK_URL"
if docker compose -f "$HERE/tracelane.compose.yml" -p "$COMPOSE_PROJECT" up -d --build >"$WORK_DIR/tracelane_compose.log" 2>&1; then
    COMPOSE_UP=1
    if wait_http "http://127.0.0.1:${GATEWAY_PORT}/health" 180; then
        GW_PID="$(docker compose -f "$HERE/tracelane.compose.yml" -p "$COMPOSE_PROJECT" top gateway 2>/dev/null | awk 'NR==2{print $2}')"
        log "Tracelane gateway healthy (host PID ${GW_PID:-unknown})"
        RESULT="$(run_scenario tracelane "http://127.0.0.1:${GATEWAY_PORT}" /v1/chat/completions claude-mock-gwbench "$TRACELANE_MASTER_KEY" "${GW_PID:--}")"
        if [[ "$RESULT" == OK* ]]; then
            read -r _ n p50 p95 p99 <<<"$RESULT"
            RSS="$(peak_rss_mb "$WORK_DIR/tracelane_rss.csv")"
            SPAN_COUNT="$(curl -s -m5 -u "tracelane:${CLICKHOUSE_PASSWORD}" \
                "http://127.0.0.1:8123/?query=SELECT%20count()%20FROM%20tracelane.spans%20FORMAT%20TabSeparated" 2>/dev/null || echo "?")"
            append_row tracelane ok "$TRACELANE_SHA" "$n" "$p50" "$p95" "$p99" "$RSS" "capture proof: ${SPAN_COUNT} rows in tracelane.spans after the run"
        else
            # A release-build gateway pointed at a loopback ANTHROPIC_BASE_URL
            # hits its OWN SSRF guard (crates/gateway/src/ssrf_guard.rs) — the
            # loopback bypass is `#[cfg(debug_assertions)]`-gated and hard-off
            # in release, by design (Opus-rereview M-4). Surface that specific
            # cause when it's the one present, instead of the generic
            # "N/M failed" from run_scenario.
            SPECIFIC_REASON="$(docker compose -f "$HERE/tracelane.compose.yml" -p "$COMPOSE_PROJECT" logs gateway 2>&1 \
                | grep -o 'SSRF guard rejected [A-Za-z ]*' | head -1)"
            if [ -n "$SPECIFIC_REASON" ]; then
                NOTE="CANNOT DETERMINE — ${SPECIFIC_REASON}: a release-build gateway cannot be pointed at a loopback ANTHROPIC_BASE_URL (crates/gateway/src/ssrf_guard.rs — the loopback bypass is debug-only by design, no release override exists). Every other gateway in this comparison has no equivalent guard."
            else
                NOTE="${RESULT#CANNOT DETERMINE — }"
            fi
            append_row tracelane "CANNOT_DETERMINE" "$TRACELANE_SHA" "" "" "" "" "" "$NOTE"
        fi
    else
        log "FATAL for this gateway: Tracelane /health never came up"
        docker compose -f "$HERE/tracelane.compose.yml" -p "$COMPOSE_PROJECT" logs gateway 2>&1 | tail -n40 >"$WORK_DIR/tracelane_health_fail.log"
        append_row tracelane "CANNOT_DETERMINE" "$TRACELANE_SHA" "" "" "" "" "" "/health never returned 200 within 180s: $(tail -n3 "$WORK_DIR/tracelane_health_fail.log" | tr '\n' ' ' | tr ',' ';')"
    fi
    docker compose -f "$HERE/tracelane.compose.yml" -p "$COMPOSE_PROJECT" down -v --remove-orphans >/dev/null 2>&1
    COMPOSE_UP=0
else
    log "FATAL for this gateway: docker compose up failed"
    append_row tracelane "CANNOT_DETERMINE" "$TRACELANE_SHA" "" "" "" "" "" "docker compose up --build failed: $(tail -n5 "$WORK_DIR/tracelane_compose.log" | tr '\n' ' ' | tr ',' ';')"
fi

# ── 4. LiteLLM Python proxy ──────────────────────────────────────────────────

log "starting LiteLLM Python proxy on :${LITELLM_PORT}"
mkdir -p "$WORK_DIR/litellm-python"
sed "s#__MOCK_URL__#${MOCK_URL}#g" "$HERE/configs/litellm-python.config.yaml" >"$WORK_DIR/litellm-python/config.yaml"
(
    LITELLM_MASTER_KEY=gwbench "$VENV_DIR/bin/litellm" --config "$WORK_DIR/litellm-python/config.yaml" --port $LITELLM_PORT \
        >"$WORK_DIR/litellm_python.log" 2>&1
) &
LITELLM_PID=$!
PIDS_TO_KILL+=("$LITELLM_PID")
if wait_port 127.0.0.1 "$LITELLM_PORT" 90; then
    RESULT="$(run_scenario litellm-python "http://127.0.0.1:${LITELLM_PORT}" /v1/chat/completions mock gwbench "$LITELLM_PID")"
    if [[ "$RESULT" == OK* ]]; then
        read -r _ n p50 p95 p99 <<<"$RESULT"
        RSS="$(peak_rss_mb "$WORK_DIR/litellm-python_rss.csv")"
        append_row litellm-python ok "$LITELLM_VERSION" "$n" "$p50" "$p95" "$p99" "$RSS" ""
    else
        append_row litellm-python "CANNOT_DETERMINE" "$LITELLM_VERSION" "" "" "" "" "" "${RESULT#CANNOT DETERMINE — }"
    fi
else
    log "FATAL for this gateway: LiteLLM Python never came up"
    append_row litellm-python "CANNOT_DETERMINE" "$LITELLM_VERSION" "" "" "" "" "" "server never answered within 90s: $(tail -n5 "$WORK_DIR/litellm_python.log" | tr '\n' ' ' | tr ',' ';')"
fi
kill -9 "$LITELLM_PID" >/dev/null 2>&1 || true

# ── 5. Portkey OSS gateway (npx) ─────────────────────────────────────────────

log "starting Portkey gateway on :${PORTKEY_PORT}"
(npx -y @portkey-ai/gateway >"$WORK_DIR/portkey.log" 2>&1) &
PORTKEY_PID=$!
PIDS_TO_KILL+=("$PORTKEY_PID")
if wait_port 127.0.0.1 "$PORTKEY_PORT" 60; then
    PORTKEY_VERSION="$(npm view @portkey-ai/gateway version 2>/dev/null || echo unknown)"
    # Portkey routes by header, not by model string: x-portkey-provider tells it
    # the request/response shape (openai = pass-through, since the mock already
    # speaks OpenAI at /v1/chat/completions), x-portkey-custom-host is the mock.
    RESULT="$(GWBENCH_EXTRA_HEADERS="x-portkey-provider:openai|x-portkey-custom-host:${MOCK_URL}/v1" \
        run_scenario portkey "http://127.0.0.1:${PORTKEY_PORT}" /v1/chat/completions mock dummy "$PORTKEY_PID")"
    if [[ "$RESULT" == OK* ]]; then
        read -r _ n p50 p95 p99 <<<"$RESULT"
        RSS="$(peak_rss_mb "$WORK_DIR/portkey_rss.csv")"
        append_row portkey ok "$PORTKEY_VERSION" "$n" "$p50" "$p95" "$p99" "$RSS" ""
    else
        append_row portkey "CANNOT_DETERMINE" "$PORTKEY_VERSION" "" "" "" "" "" "${RESULT#CANNOT DETERMINE — }"
    fi
else
    log "FATAL for this gateway: Portkey never came up"
    append_row portkey "CANNOT_DETERMINE" "unknown" "" "" "" "" "" "server never answered within 120s: $(tail -n5 "$WORK_DIR/portkey.log" | tr '\n' ' ' | tr ',' ';')"
fi
kill -9 "$PORTKEY_PID" >/dev/null 2>&1 || true

# ── 6. Bifrost (npx) ─────────────────────────────────────────────────────────

log "starting Bifrost on :${BIFROST_PORT}"
mkdir -p "$WORK_DIR/bifrost-app-dir"
sed "s#__MOCK_URL__#${MOCK_URL}#g" "$HERE/configs/bifrost.config.json" >"$WORK_DIR/bifrost-app-dir/config.json"
(npx -y @maximhq/bifrost --app-dir "$WORK_DIR/bifrost-app-dir" --host 127.0.0.1 --port $BIFROST_PORT \
    >"$WORK_DIR/bifrost.log" 2>&1) &
BIFROST_PID=$!
PIDS_TO_KILL+=("$BIFROST_PID")
if wait_port 127.0.0.1 "$BIFROST_PORT" 120; then
    BIFROST_VERSION="$(grep -oP '\.cache/bifrost/\K[^/]+' "$WORK_DIR/bifrost.log" | head -1 || echo unknown)"
    RESULT="$(run_scenario bifrost "http://127.0.0.1:${BIFROST_PORT}" /openai/v1/chat/completions openai/mock dummy "$BIFROST_PID")"
    if [[ "$RESULT" == OK* ]]; then
        read -r _ n p50 p95 p99 <<<"$RESULT"
        RSS="$(peak_rss_mb "$WORK_DIR/bifrost_rss.csv")"
        append_row bifrost ok "${BIFROST_VERSION:-unknown}" "$n" "$p50" "$p95" "$p99" "$RSS" ""
    else
        append_row bifrost "CANNOT_DETERMINE" "${BIFROST_VERSION:-unknown}" "" "" "" "" "" "${RESULT#CANNOT DETERMINE — }"
    fi
else
    log "FATAL for this gateway: Bifrost never came up"
    append_row bifrost "CANNOT_DETERMINE" "unknown" "" "" "" "" "" "server never answered within 120s: $(tail -n5 "$WORK_DIR/bifrost.log" | tr '\n' ' ' | tr ',' ';')"
fi
kill -9 "$BIFROST_PID" >/dev/null 2>&1 || true

# ── 7. LiteLLM Rust — no public build ────────────────────────────────────────

append_row litellm-rust "CANNOT_DETERMINE" "" "" "" "" "" "" "no public build — LiteLLM's own harness README builds it from a private branch (/home/ubuntu/repos/litellm/litellm-rust @ litellm_rust_messages_route) on their machine; never skip silently, per spec"

log "wrote $OUT_CSV"
cat "$OUT_CSV" >&2

# ── 8. overhead computation ──────────────────────────────────────────────────

"$VENV_DIR/bin/python" "$HERE/analyze/compute_overhead.py" "$OUT_CSV" || true

log "done"
