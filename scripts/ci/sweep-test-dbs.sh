#!/usr/bin/env bash
# Drop leftover per-test Postgres databases from a LOCAL test cluster.
#
# Why: the gateway's real-Postgres fixtures create a fresh database per test and never drop it —
# `tlane_schema_<uuid>` (`entitlement_cache.rs` `fresh_pool`, used by every `*_pg_tests.rs`), plus
# `tlane_it_<hex>`, `tlane_membership_<hex>` and `issuance_<hex>`. CI uses a throwaway container, so
# nothing accumulates there, but a long-lived cluster does: on 2026-11-09 a cloud session held 1,360
# of them (14 GB) and filled its disk mid-build (runbooks/RCA-pg-test-db-leak.md).
#
# This script DROPS DATABASES, so "local only" is enforced in three layers, and the selftest's own
# live phase passes through the same layers before it creates anything:
#   1. the URL must match one anchored shape — postgres[ql]://user[:pass]@{127.0.0.1|[::1]}[:port]/db —
#      so there is NO query string (libpq honours ?host= / ?hostaddr= / ?service= over the authority,
#      which is how the earlier glob was bypassable), exactly one '@', no ',' multi-host list, and no
#      hostname to re-resolve between connections;
#   2. every psql call runs with -X (no psqlrc, whose \connect would redirect it) and with the libpq
#      variables that can redirect a connection unset (PGHOSTADDR overrides the URL's host; PGSERVICE
#      can supply a hostaddr);
#   3. before anything is dropped, the SERVER must report a loopback inet_server_addr().
#      Known limit: a port-forward that terminates on another machine's loopback passes layer 3;
#      layers 1–2 still require that the forward was set up on purpose on this host.
# Only exact test-fixture names with NO open connection are dropped, so a running test keeps its
# database. Known limit: a database created a moment before its test connects can be dropped in that
# gap if a sweep runs concurrently on the same cluster — run it between test runs, not during one.
#
# Usage: sweep-test-dbs.sh [--selftest]   (reads $POSTGRES_TEST_URL; no URL = nothing to do)
set -uo pipefail

# Exactly the fixtures' format: <prefix>_<uuid simple()> (32 lowercase hex). Nothing else is ever dropped.
NAME_RE='^(tlane_schema|tlane_it|tlane_membership|issuance)_[0-9a-f]{32}$'

local_url() {
  # userinfo is RFC 3986 unreserved characters or %XX only: no quote, '$', '`', ';', '&', '|' or space,
  # so nothing in an accepted URL is meaningful to a shell even if a caller mishandles it.
  [[ "$1" =~ ^postgres(ql)?://[A-Za-z0-9._~-]+(:([A-Za-z0-9._~-]|%[0-9A-Fa-f]{2})*)?@(127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?/[A-Za-z0-9_]+$ ]]
}

loopback_addr() {
  case "$1" in 127.0.0.1|::1) return 0 ;; *) return 1 ;; esac
}

# psql with no psqlrc and every libpq variable that can redirect the connection removed.
q() {
  # -X skips every psqlrc (~/.psqlrc, the system one and $PSQLRC); PGOPTIONS could set a search_path
  # that shadows inet_server_addr, so it goes too and the check names pg_catalog explicitly.
  env -u PGHOST -u PGHOSTADDR -u PGPORT -u PGSERVICE -u PGSERVICEFILE -u PGSYSCONFDIR -u PGDATABASE \
    -u PGOPTIONS psql -X "$@"
}

# Layers 1 and 3. Returns 0 only for a loopback URL whose server reports a loopback address.
guard() {
  local url="$1" addr
  local_url "$url" || { echo "sweep-test-dbs: REFUSED — not a local URL" >&2; return 2; }
  addr="$(q "$url" -Atc "SELECT coalesce(host(pg_catalog.inet_server_addr()), '')" 2>/dev/null)" \
    || { echo "sweep-test-dbs: cannot connect — nothing dropped" >&2; return 3; }
  loopback_addr "$addr" || { echo "sweep-test-dbs: REFUSED — server address '$addr' is not loopback" >&2; return 2; }
}

# Test-fixture databases with no open connection.
candidates() {
  q "$1" -Atc "SELECT datname FROM pg_database d WHERE datname ~ '$NAME_RE' AND NOT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datname = d.datname)"
}

# Drop one database. The loopback check and the DROP run in ONE psql session, so the server that
# passes the check is the server that drops; the name goes in as a psql variable, quoted by psql
# itself (:"d"), never spliced into SQL.
# The in-session allow-list. A constant; the selftest narrows it to prove the session check refuses.
LOOPBACK_SQL="'127.0.0.1', '::1'"
drop_one() {
  q "$1" -q -v ON_ERROR_STOP=1 -v d="$2" -v allowed="$LOOPBACK_SQL" -f - <<'SQL'
SELECT coalesce(host(pg_catalog.inet_server_addr()) IN (:allowed), false) AS loopback \gset
\if :loopback
DROP DATABASE IF EXISTS :"d";
\else
\echo 'sweep-test-dbs: REFUSED in session: server is not loopback'
SELECT 1/0;
\endif
SQL
}

sweep() {
  local url="$1" n=0 d
  guard "$url" || return $?
  while read -r d; do
    # The server's answer is not trusted: re-check every name on this side before it is used.
    [[ "$d" =~ $NAME_RE ]] || continue
    drop_one "$url" "$d" >/dev/null 2>&1 && n=$((n + 1))
  done < <(candidates "$url" 2>/dev/null)
  echo "sweep-test-dbs: dropped $n leftover test database(s)"
}

# Selftest only: run sweep with extra variables in the environment. The URL is passed as an argument
# and never spliced into a command string, so no character in it is evaluated by a shell.
# Usage: sweep_under_env <url> [NAME=value ...] — each variable is its own argument, never word-split.
sweep_under_env() {
  local url="$1"; shift
  ( for kv in "$@"; do export "$kv"; done; export PGCONNECT_TIMEOUT=2; sweep "$url" )
}

if [ "${1:-}" = "--selftest" ]; then
  rc=0
  fail() { echo "SELFTEST FAIL: $*"; rc=1; }
  # 1. URL shapes that must be REFUSED (each one either names a non-local host or lets libpq pick one).
  for bad in \
    "postgres://u:p@db.example.com:5432/x" \
    "postgres://u@127.0.0.1:5432/x?host=db.example.com" \
    "postgres://u@127.0.0.1/x?hostaddr=10.0.0.5" \
    "postgres://u@127.0.0.1:5432/x?service=prod" \
    "postgres://u@127.0.0.1:5432,db.example.com:5432/x" \
    "postgres://u@db.example.com@127.0.0.1:5432/x" \
    "postgres://u:p@x@127.0.0.1:5432/x" \
    "postgres://u@localhost:5432/x" \
    "postgres://u@127.0.0.1.nip.io:5432/x" \
    "postgres://127.0.0.1:5432/x" \
    "postgres://u@127.0.0.1:5432/" \
    "host=127.0.0.1 dbname=x" \
    "postgres://u'x'@127.0.0.1:5432/x" \
    'postgres://u$(id)@127.0.0.1:5432/x' \
    'postgres://u`id`@127.0.0.1:5432/x' \
    "postgres://u;id@127.0.0.1:5432/x" \
    "postgres://u:p&id@127.0.0.1:5432/x" \
    "postgres://u:p|id@127.0.0.1:5432/x" \
    "postgres://u x@127.0.0.1:5432/x" \
    "host=db.example.com dbname=postgres://u@127.0.0.1/x" \
    "postgres://u@127.0.0.1/x
postgres://u@db.example.com/x"; do
    local_url "$bad" && fail "accepted $bad"
  done
  for good in "postgres://u:p@127.0.0.1:5432/x" "postgresql://u@127.0.0.1/x" "postgres://u@[::1]:5432/x" "postgres://u:p%27q@127.0.0.1/x"; do
    local_url "$good" || fail "refused $good"
  done
  # 2. A non-loopback server address is refused (layer 3).
  for a in 10.0.0.5 192.0.2.1 "" 2001:db8::1; do
    loopback_addr "$a" && fail "server address '$a' treated as loopback"
  done
  { loopback_addr 127.0.0.1 && loopback_addr ::1; } || fail "loopback refused"
  # The env-runner never evaluates the URL: a hostile one, with sweep stubbed, must not run a command.
  marker="$(mktemp -u)"
  ( sweep() { :; }; sweep_under_env "postgres://u'\$(touch $marker)'@127.0.0.1/x" "PGHOSTADDR=192.0.2.1" )
  [ -e "$marker" ] && { fail "a shell command inside a URL was executed"; rm -f "$marker"; }
  # 3. Names: fixture names match, everything else does not.
  h=0123456789abcdef0123456789abcdef
  for n in "tlane_schema_$h" "tlane_it_$h" "tlane_membership_$h" "issuance_$h"; do
    [[ "$n" =~ $NAME_RE ]] || fail "fixture name $n not matched"
  done
  for n in tracelane postgres issuance_prod tlane_it_x tlane_schema_staging_copy tlane_schema_ab12_cd \
    "tlane_schema_${h}x" "tlane_schema_${h}0" "tlane_schema_${h^^}" "prod_tlane_schema_$h" "tlane_schema_$h.bak" \
    tlane_schema_abc 'tlane_schema_x"; select 1; --'; do
    [[ "$n" =~ $NAME_RE ]] && fail "non-fixture name '$n' matched"
  done

  url="${POSTGRES_TEST_URL:-}"
  if [ -z "$url" ]; then
    [ "$rc" = 0 ] && echo "SELFTEST PASS (offline cases only) — live cases CANNOT DETERMINE: no POSTGRES_TEST_URL"
    exit "$rc"
  fi
  # 4. sweep() with psql stubbed. drop_one is stubbed to record what it was asked to drop.
  log="$(mktemp)"
  #    (a) The server reports a non-loopback address: sweep() must refuse and drop nothing. This fails
  #        if guard() is removed from sweep() or reduced to the URL check, not only if guard() breaks.
  for a in 10.0.0.5 ""; do
    : >"$log"
    ( q() { echo "$a"; }; candidates() { echo "tlane_schema_$h"; }; drop_one() { echo "$2" >>"$log"; }
      sweep "postgres://u@127.0.0.1:5432/x" ) >/dev/null 2>&1 && fail "sweep accepted a server reporting '$a'"
    [ -s "$log" ] && fail "sweep dropped on a server reporting '$a'"
  done
  #    (b) A loopback server returns hostile and non-fixture names: only the fixture name is dropped.
  : >"$log"
  ( q() { echo 127.0.0.1; }
    candidates() { printf '%s\n' 'x"; DROP DATABASE tracelane; --' tlane_schema_staging_copy tracelane "tlane_schema_$h"; }
    drop_one() { echo "$2" >>"$log"; }
    sweep "postgres://u@127.0.0.1:5432/x" ) >/dev/null 2>&1
  [ "$(cat "$log")" = "tlane_schema_$h" ] || fail "sweep acted on a name the server returned that is not a fixture name: $(tr '\n' '|' <"$log")"
  rm -f "$log"
  # The live phase creates and drops databases, so it passes the same guard first.
  guard "$url" || { echo "SELFTEST REFUSED: live cases run only against a loopback test cluster"; exit 2; }
  # 5. Live: idle leftover dropped; in-use, non-fixture and unsafe-named databases are never candidates;
  #    hostile PGHOSTADDR / PGSERVICE / PSQLRC in the environment do not redirect the sweep.
  hx() { printf '%s' "$1$$$(date +%s%N)" | sha256sum | cut -c1-32; }
  idle="tlane_schema_$(hx idle)"; busy="tlane_schema_$(hx busy)"; other="tlane_schema_selftest_keep_$$"
  odd='tlane_schema_x"; select 1; --'"$$"
  for d in "$idle" "$busy" "$other" "$odd"; do q "$url" -qc "CREATE DATABASE \"${d//\"/\"\"}\"" >/dev/null; done
  q "${url%/*}/$busy" -qc "SELECT pg_sleep(60)" >/dev/null 2>&1 &
  holder=$!
  for _ in $(seq 1 20); do
    [ "$(q "$url" -Atc "SELECT count(*) FROM pg_stat_activity WHERE datname='$busy'")" -ge 1 ] && break
    sleep 0.2
  done
  cands="$(candidates "$url")"
  grep -qxF "$idle" <<<"$cands" || fail "idle leftover is not a candidate"
  grep -qxF "$busy" <<<"$cands" && fail "a database in use is a candidate (connection filter broken)"
  grep -qxF "$other" <<<"$cands" && fail "a non-fixture database is a candidate"
  grep -qF 'select 1' <<<"$cands" && fail "a database with an unsafe name is a candidate"
  tmp="$(mktemp -d)"
  printf '[hostile]\nhostaddr=192.0.2.1\n' >"$tmp/pg_service.conf"
  printf '\\connect postgres://nobody@192.0.2.1/x\n' >"$tmp/psqlrc"
  mkdir "$tmp/home" && cp "$tmp/psqlrc" "$tmp/home/.psqlrc"
  for envset in "PGHOSTADDR=192.0.2.1" "PGSERVICEFILE=$tmp/pg_service.conf|PGSERVICE=hostile" "PSQLRC=$tmp/psqlrc" \
    "HOME=$tmp/home" "PGOPTIONS=-c search_path=nowhere"; do
    q "$url" -qc "CREATE DATABASE \"$idle\"" >/dev/null 2>&1
    IFS='|' read -r -a kvs <<<"$envset"
    sweep_under_env "$url" "${kvs[@]}" >/dev/null 2>&1
    [ "$(q "$url" -Atc "SELECT count(*) FROM pg_database WHERE datname='$idle'")" = "0" ] \
      || fail "sweep under '$envset' did not reach the local cluster (redirected)"
  done
  rm -rf "$tmp"
  for d in "$other" "$odd" "$busy"; do
    [ "$(q "$url" -Atc "SELECT count(*) FROM pg_database WHERE datname=\$n\$$d\$n\$")" = "1" ] || fail "a real sweep dropped '$d'"
  done
  # guard() names pg_catalog.inet_server_addr, so a same-named function earlier on the search_path cannot
  # answer for it. Proven with PGOPTIONS let through (it is also unset in q(); that layer backs this one up).
  sh="selftest_shadow_$$"
  q "$url" -qc "CREATE SCHEMA $sh; CREATE FUNCTION $sh.inet_server_addr() RETURNS inet LANGUAGE sql AS \$\$SELECT '10.0.0.5'::inet\$\$" >/dev/null 2>&1
  ( q() { env PGOPTIONS="-c search_path=$sh,pg_catalog" psql -X "$@"; }; guard "$url" ) >/dev/null 2>&1 \
    || fail "guard() was answered by a shadowing inet_server_addr on the search_path"
  q "$url" -qc "DROP SCHEMA $sh CASCADE" >/dev/null 2>&1
  # drop_one refuses in-session when the server is not on its allow-list (the allow-list is narrowed here,
  # since no local server reports a non-loopback address), and never forces out a live connection.
  q "$url" -qc "CREATE DATABASE \"$idle\"" >/dev/null 2>&1
  ( LOOPBACK_SQL="'192.0.2.1'"; drop_one "$url" "$idle" ) >/dev/null 2>&1 && fail "drop_one dropped on a server outside its allow-list"
  [ "$(q "$url" -Atc "SELECT count(*) FROM pg_database WHERE datname='$idle'")" = "1" ] || fail "in-session check did not stop the drop"
  q "$url" -qc "DROP DATABASE \"$idle\"" >/dev/null 2>&1
  drop_one "$url" "$busy" >/dev/null 2>&1 && fail "drop_one dropped a database with an open connection (FORCE?)"
  # drop_one quotes the name itself: a name with '"' and ';' drops exactly that database.
  q "$url" -qc "CREATE DATABASE \"${odd//\"/\"\"}\"" >/dev/null 2>&1
  drop_one "$url" "$odd" >/dev/null 2>&1 || fail "drop_one could not drop a database whose name holds a quote"
  [ "$(q "$url" -Atc "SELECT count(*) FROM pg_database WHERE datname=\$n\$$odd\$n\$")" = "0" ] || fail "drop_one left '$odd'"
  [ "$(q "$url" -Atc "SELECT count(*) FROM pg_database WHERE datname=\$n\$$other\$n\$")" = "1" ] || fail "drop_one of '$odd' touched '$other'"
  kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null
  for d in "$idle" "$busy" "$other" "$odd"; do q "$url" -qc "DROP DATABASE IF EXISTS \"${d//\"/\"\"}\"" >/dev/null 2>&1; done
  [ "$rc" = 0 ] && echo "SELFTEST PASS: 19 unsafe URLs (7 with shell metacharacters), a URL never evaluated, 4 non-loopback addresses (and guard() refusing a non-loopback server), 9 non-fixture names refused; sweep() refuses a non-loopback server and re-checks server-returned names; idle leftover dropped; in-use, non-fixture and unsafe-named never candidates; PGHOSTADDR, PGSERVICE, PSQLRC, ~/.psqlrc and PGOPTIONS ignored; in-session check refuses; in-use never forced"
  exit "$rc"
fi

[ -n "${POSTGRES_TEST_URL:-}" ] || { echo "sweep-test-dbs: no POSTGRES_TEST_URL — nothing to do"; exit 0; }
sweep "$POSTGRES_TEST_URL"
