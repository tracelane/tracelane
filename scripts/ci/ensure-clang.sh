#!/usr/bin/env bash
# Print the path of a clang that can compile ring's C for wasm32-unknown-unknown, and export
# CC_wasm32_unknown_unknown (+ LD_LIBRARY_PATH) to $GITHUB_ENV when running in Actions.
# The self-hosted runner has no clang and no sudo, so when none is on PATH this fetches the
# distro's own clang packages WITHOUT root (apt-get download + dpkg -x) into a per-user cache,
# once; later runs reuse it. Hosted runners and developer machines use their system clang.
# Fails CLOSED: no usable clang is an error, never a silent skip of the wasm build.
set -euo pipefail
emit() {  # $1 = clang path, $2 = extra library path (may be empty)
  local ld="${2:+$2${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}"
  ld="${ld:-${LD_LIBRARY_PATH:-}}"
  LD_LIBRARY_PATH="$ld" "$1" --version >/dev/null 2>&1 || { echo "ensure-clang: $1 does not run" >&2; exit 1; }
  if [ -n "${GITHUB_ENV:-}" ]; then
    echo "CC_wasm32_unknown_unknown=$1" >> "$GITHUB_ENV"
    [ -z "$2" ] || echo "LD_LIBRARY_PATH=$ld" >> "$GITHUB_ENV"
  fi
  echo "$1"
  exit 0
}
if command -v clang >/dev/null 2>&1; then emit "$(command -v clang)" ""; fi

pkg=$(apt-cache depends clang 2>/dev/null | awk '/Depends: clang-[0-9]+$/{print $2; exit}')
[ -n "$pkg" ] || { echo "ensure-clang: no clang package known to apt on this host" >&2; exit 1; }
v=${pkg#clang-}
root="${TL_CLANG_HOME:-$HOME/.cache/tl-clang}/$v"
bin="$root/usr/lib/llvm-$v/bin/clang"
lib="$root/usr/lib/x86_64-linux-gnu:$root/usr/lib/llvm-$v/lib"
if [ ! -x "$bin" ]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  # The four packages that make a working clang driver + its builtin headers + LLVM.
  (cd "$tmp" && apt-get download -q "$pkg" "libclang-cpp$v" "libclang-common-$v-dev" "libllvm$v" >/dev/null)
  rm -rf "$root.partial" && mkdir -p "$root.partial"   # a failed earlier extract starts over
  for d in "$tmp"/*.deb; do dpkg -x "$d" "$root.partial"; done
  rm -rf "$root" && mv "$root.partial" "$root"   # never leave a half-extracted tree in place
fi
emit "$bin" "$lib"
