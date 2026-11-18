#!/usr/bin/env bash
# Remove throwaway test containers left by a run that was killed before its EXIT trap ran.
# Usage: reap-orphan-containers.sh <name-prefix>...   (names are <prefix><pid> of the run that
# started them). A container is an orphan only when that pid no longer exists on this host
# (/proc/<pid>, not `kill -0`, which also fails for a live process of another user). A live
# run's containers are never touched; a recycled pid keeps an orphan, which is the safe error.
# Earned 2026-11-14: a killed ledger run left its Postgres on 127.0.0.1:15467 for hours and
# every later run failed to start its own (RCA-wasm-ci-missing-target.md).
# Fail-open by design: no Docker, or a failed rm, never fails the caller.
set -uo pipefail
command -v docker >/dev/null 2>&1 || exit 0
for prefix in "$@"; do
  docker ps -a --filter "name=^${prefix}" --format '{{.Names}}' 2>/dev/null | while read -r name; do
    pid="${name#"$prefix"}"
    [[ "$name" == "$prefix"* && "$pid" =~ ^[0-9]+$ ]] || continue
    [ -d "/proc/$pid" ] && continue
    echo "reaping orphaned test container $name (its run, pid $pid, is gone)" >&2
    docker rm -fv "$name" >/dev/null 2>&1 || true
  done
done
exit 0
