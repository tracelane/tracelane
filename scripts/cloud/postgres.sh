#!/usr/bin/env bash
# Local Postgres for cloud sessions (Claude Code on the web). Idempotent; never fails.
#
# Cloud sessions have no docker, so scripts/ci/run-postgres-integration.sh would SKIP and the
# `*_pg_tests.rs` suites (action control, approvals) could not run. Both honour
# $POSTGRES_TEST_URL; this provides a throwaway local cluster behind it. setup.sh is the
# toolchain bootstrap; this is the one service it leaves out. Rules: .claude/rules/autonomy.md.
#
# Run in the background by scripts/hooks/session-start-cloud.sh (CLAUDE_CODE_REMOTE=true), which
# exports $POSTGRES_TEST_URL; run it by hand anywhere else. Points only at
# 127.0.0.1 — never at a control plane.
set -uo pipefail
# One run at a time: a hand re-run during the hook's background apt would hit the apt lock.
# `9>&-` on anything that can start the server, or the postmaster inherits and holds the lock.
exec 9>/tmp/cloud-postgres.lock && flock 9

URL="postgres://tracelane:tracelane_dev@127.0.0.1:5432/tracelane"
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"
# As postgres. `$SUDO -u postgres` would be a bare `-u postgres …` when root (found 2026-10-29
# on a fresh ubuntu:24.04 run as root, the cloud default).
as_pg() { if [ "$(id -u)" -eq 0 ]; then runuser -u postgres -- "$@"; else sudo -u postgres "$@"; fi; }

if ! command -v pg_ctlcluster >/dev/null 2>&1; then
  $SUDO apt-get update -qq >/dev/null 2>&1
  $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postgresql postgresql-client >/dev/null 2>&1 9>&- \
    || { echo "cloud postgres: install FAILED — real-Postgres tests CANNOT RUN here"; exit 0; }
fi

ver="$(ls /etc/postgresql 2>/dev/null | sort -V | tail -1)"
[ -n "$ver" ] && $SUDO pg_ctlcluster "$ver" main start >/dev/null 2>&1 9>&-
for _ in $(seq 1 20); do
  as_pg psql -tAc "SELECT 1" >/dev/null 2>&1 && break
  sleep 0.5
done

# B-632: the test role is NOT a superuser. This script also runs on the persistent CI VM, where a
# loopback superuser with a published password lets any local process run `COPY ... PROGRAM` as
# the postgres OS user. The fixtures need only LOGIN + CREATEDB (per-test databases, own schema,
# plpgsql triggers) plus pg_monitor for the migrate.sh selftest. An existing role from an older
# run is demoted in place.
as_pg psql -q -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<'SQL'
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='tracelane') THEN
    CREATE ROLE tracelane LOGIN CREATEDB NOSUPERUSER NOCREATEROLE PASSWORD 'tracelane_dev';
  ELSE
    ALTER ROLE tracelane LOGIN CREATEDB NOSUPERUSER NOCREATEROLE;
  END IF;
END $$;
-- migrate.sh --selftest proves a URL role override is refused by switching to pg_monitor, a
-- read-only built-in monitoring role (no file or program access).
GRANT pg_monitor TO tracelane;
SQL
as_pg psql -tAc "SELECT 1 FROM pg_database WHERE datname='tracelane'" 2>/dev/null | grep -q 1 \
  || as_pg createdb -O tracelane tracelane >/dev/null 2>&1

if [ "$(psql "$URL" -tAc "SELECT rolsuper FROM pg_roles WHERE rolname=current_user" 2>/dev/null)" = "t" ]; then
  echo "cloud postgres: test role is still SUPERUSER — refusing to advertise it (B-632)"
elif psql "$URL" -tAc "SELECT 1" >/dev/null 2>&1; then
  # Per-test databases are never dropped by the fixtures; clear any left by an earlier session
  # before they fill the disk (runbooks/RCA-pg-test-db-leak.md).
  POSTGRES_TEST_URL="$URL" bash "$(dirname "$0")/../ci/sweep-test-dbs.sh" 9>&- || true
  echo "cloud postgres: ${ver:-?} ready — POSTGRES_TEST_URL=$URL"
else
  echo "cloud postgres: NOT reachable at $URL — real-Postgres tests CANNOT RUN here"
fi
exit 0
