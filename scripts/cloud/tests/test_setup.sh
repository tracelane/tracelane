#!/usr/bin/env bash
# Fast, offline bootstrap contracts. The clean-container proof lives in infra/gcp/tests.
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
if [[ ! -f "$root/scripts/cloud/setup.sh" ]]; then
    echo 'FAIL: bootstrap must provide a read-only --check entry point'
    exit 1
fi
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# Never let fixture identities or paths leak into a linked worktree.
while IFS='=' read -r key _; do
    case "$key" in GIT_*) unset "$key" ;; esac
done < <(env)
export HOME="$tmp/home" XDG_CONFIG_HOME="$tmp/config" GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME/.local/bin" "$tmp/repo/scripts/cloud" "$tmp/repo/.githooks" "$tmp/bin"
cp "$root/scripts/cloud/setup.sh" "$tmp/repo/scripts/cloud/"
cp "$root/rust-toolchain.toml" "$tmp/repo/"
cp "$root/.githooks/commit-authors.allow" "$tmp/repo/.githooks/"
mkdir -p "$tmp/repo/scripts/ci/requirements"
cp "$root/scripts/ci/requirements/python-ci.txt" "$tmp/repo/scripts/ci/requirements/"
git -C "$tmp/repo" init -q
# A hermetic PATH deliberately lacks every installable tool.
for cmd in timeout ln bash sh mv dirname pwd sed awk grep cat uname mktemp rm mkdir chmod head cut tr sha256sum tar install; do
    ln -s "$(command -v "$cmd")" "$tmp/bin/$cmd"
done
ln -s "$(command -v git)" "$tmp/bin/git"
python_bin="$(command -v python3)"
export PATH="$tmp/bin" RUSTUP_HOME="$tmp/rustup" CARGO_HOME="$tmp/cargo"
export CALLS="$tmp/calls"
export COREPACK_HOME="$HOME/.cache/node/corepack"
: > "$CALLS"
for cmd in curl apt-get corepack; do
    cat > "$tmp/bin/$cmd" <<'SH'
#!/usr/bin/env bash
printf '%s %s\n' "$0" "$*" >> "$CALLS"
echo 'unexpected install/network call' >&2
exit 99
SH
    chmod +x "$tmp/bin/$cmd"
done
before="$(cat "$tmp/repo/.git/config")"
if output="$(bash "$tmp/repo/scripts/cloud/setup.sh" --check 2>&1)"; then
    echo 'FAIL: missing tools must fail --check'; exit 1
fi
for missing in rust pnpm uv gitleaks gh cmake; do
    if [[ "$output" != *"$missing"* ]]; then
        echo "FAIL: --check did not list missing $missing: $output"; exit 1
    fi
done
[[ ! -s "$CALLS" ]] || { echo 'FAIL: --check invoked an installer/network client'; cat "$CALLS"; exit 1; }
[[ "$(cat "$tmp/repo/.git/config")" == "$before" ]] || { echo 'FAIL: --check changed Git config'; exit 1; }
echo 'PASS: missing_tools_are_listed_without_install_or_git_writes'
if bash "$tmp/repo/scripts/cloud/setup.sh" --unknown > "$tmp/usage" 2>&1; then
    echo 'FAIL: unknown arguments must fail'; exit 1
fi
[[ ! -s "$CALLS" ]] || { echo 'FAIL: invalid arguments caused side effects'; exit 1; }
echo 'PASS: invalid_arguments_do_not_install'

# Docker-unavailable is an explicit skip, never a claimed build pass.
mkdir -p "$tmp/repo/infra/gcp/tests"
/bin/cp "$root/infra/gcp/tests/test_setup.sh" "$tmp/repo/infra/gcp/tests/"
cat > "$tmp/bin/docker" <<'SH'
#!/usr/bin/env bash
exit 1
SH
chmod +x "$tmp/bin/docker"
output="$(bash "$tmp/repo/infra/gcp/tests/test_setup.sh")"
[[ "$output" == 'SKIPPED: no docker' ]] || { echo "FAIL: no Docker: $output"; exit 1; }
echo 'PASS: docker_unavailable_is_explicit_skip'
if output="$(bash "$tmp/repo/infra/gcp/tests/test_setup.sh" --check-only 2>&1)"; then
    echo 'FAIL: --check-only hid missing tools'; exit 1
fi
[[ "$output" == *'MISSING:'* ]] || { echo "FAIL: --check-only did not forward check: $output"; exit 1; }
echo 'PASS: check_only_forwards_failure'

# A fully populated fixture catches writes that the missing-tool branch cannot.
mkdir -p "$COREPACK_HOME/v1/pnpm/9.15.0/bin"
printf '{"name":"pnpm","version":"9.15.0"}\n' > "$COREPACK_HOME/v1/pnpm/9.15.0/package.json"
printf '{"bin":{"pnpm":"./bin/pnpm.cjs"}}\n' > "$COREPACK_HOME/v1/pnpm/9.15.0/.corepack"
: > "$COREPACK_HOME/v1/pnpm/9.15.0/bin/pnpm.cjs"
ln -s "$python_bin" "$tmp/bin/python3"
for cmd in rustup cmake make gcc g++ pkg-config node corepack pnpm uv gh; do
    cat > "$tmp/bin/$cmd" <<'SH'
#!/usr/bin/env bash
case "$0" in
    */rustup) if [[ "$*" == *metadata* ]]; then echo mutation > cargo-cache-write; fi ;;
    */pnpm) echo 9.15.0 ;;
esac
exit 0
SH
    chmod +x "$tmp/bin/$cmd"
done
rust_bin="$RUSTUP_HOME/toolchains/1.95-$(uname -m)-unknown-linux-gnu/bin"
mkdir -p "$rust_bin"
for tool in rustc cargo rustfmt cargo-clippy; do printf '#!/usr/bin/env bash\nexit 0\n' > "$rust_bin/$tool"; chmod +x "$rust_bin/$tool"; done
mkdir -p "$tmp/repo/.venv/bin" "$tmp/repo/node_modules" "$tmp/repo/apps/web/node_modules/.bin" "$tmp/repo/pytest"
ln -s "$python_bin" "$tmp/repo/.venv/bin/python"
printf '# fixture\n' > "$tmp/repo/pytest/__init__.py"
printf 'print("pytest fixture")\n' > "$tmp/repo/pytest/__main__.py"
: > "$tmp/repo/scripts/ci/requirements/python-ci.txt"
: > "$tmp/repo/node_modules/.modules.yaml"
printf 'version = 4\npackage = []\n' > "$tmp/repo/Cargo.lock"
printf '#!/usr/bin/env bash\necho 8.21.2\n' > "$HOME/.local/bin/gitleaks"
printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/repo/.venv/bin/ruff"
cp_command=/bin/cp
"$cp_command" "$tmp/repo/.venv/bin/ruff" "$tmp/repo/apps/web/node_modules/.bin/tsc"
chmod +x "$HOME/.local/bin/gitleaks" "$tmp/repo/.venv/bin/ruff" "$tmp/repo/apps/web/node_modules/.bin/tsc"
mkdir -p "$tmp/repo/packages/verifier-typescript/dist"
for artifact in index.js index.d.ts node.js node.d.ts; do
    : > "$tmp/repo/packages/verifier-typescript/dist/$artifact"
done
git -C "$tmp/repo" config core.hooksPath .githooks
git -C "$tmp/repo" config user.email novstar89@gmail.com
git -C "$tmp/repo" config user.name Fixture
/usr/bin/find "$tmp/repo" -printf '%p %s %T@\n' | /usr/bin/sort > "$tmp/before"
if ! output="$(bash "$tmp/repo/scripts/cloud/setup.sh" --check 2>&1)"; then
    echo "FAIL: populated --check: $output"; exit 1
fi
/usr/bin/find "$tmp/repo" -printf '%p %s %T@\n' | /usr/bin/sort > "$tmp/after"
if ! /usr/bin/diff -u "$tmp/before" "$tmp/after"; then
    echo 'FAIL: populated_check_must_not_write'; exit 1
fi
echo 'PASS: populated_check_must_not_write'
# rustup creates RUSTUP_HOME even with RUSTUP_AUTO_INSTALL=0, so --check reads toolchain files instead.
cat > "$tmp/bin/rustup" <<'SH'
#!/usr/bin/env bash
echo "RUSTUP INVOKED $*" >> "$CALLS"
exit 0
SH
: > "$CALLS"
if ! output="$(bash "$tmp/repo/scripts/cloud/setup.sh" --check 2>&1)" || [[ -s "$CALLS" ]]; then
    echo "FAIL: check_reads_toolchain_without_invoking_rustup: $output"; cat "$CALLS"; exit 1
fi
mv "$RUSTUP_HOME" "$tmp/rustup.saved"
if output="$(bash "$tmp/repo/scripts/cloud/setup.sh" --check 2>&1)" || [[ "$output" != *'MISSING: Rust 1.95'* ]] ||
   [[ -s "$CALLS" || -e "$RUSTUP_HOME" ]]; then
    echo "FAIL: absent_toolchain_listed_without_invoking_rustup: $output"; cat "$CALLS"; exit 1
fi
mv "$tmp/rustup.saved" "$RUSTUP_HOME"
printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/rustup"
echo 'PASS: check_reads_toolchain_without_invoking_rustup'
rm "$tmp/repo/packages/verifier-typescript/dist/index.d.ts"
if output="$(bash "$tmp/repo/scripts/cloud/setup.sh" --check 2>&1)"; then
    echo 'FAIL: missing_verifier_build_must_fail_check'; exit 1
fi
[[ "$output" == *'audit-verifier build'* ]] || { echo "FAIL: missing verifier not listed: $output"; exit 1; }
: > "$tmp/repo/packages/verifier-typescript/dist/index.d.ts"
echo 'PASS: missing_verifier_build_must_fail_check'
rm "$HOME/.local/bin/gitleaks"

# Exercise the real checksum verifier with a tampered download. All other tool
# boundaries are stubs; tar must never see the unverified bytes.
for cmd in rustup node corepack pnpm uv gh; do
    cat > "$tmp/bin/$cmd" <<'SH'
#!/usr/bin/env bash
case "$0" in
    */pnpm) [[ "${1:-}" != --version ]] || echo 9.15.0 ;;
esac
exit 0
SH
    chmod +x "$tmp/bin/$cmd"
done
cat > "$tmp/bin/id" <<'SH'
#!/usr/bin/env bash
echo 1000
SH
cat > "$tmp/bin/curl" <<'SH'
#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
    if [[ "$1" == -o ]]; then printf 'tampered archive' > "$2"; exit 0; fi
    shift
done
exit 1
SH
rm "$tmp/bin/tar"
cat > "$tmp/bin/tar" <<'SH'
#!/usr/bin/env bash
echo 'UNVERIFIED EXTRACTION' >> "$CALLS"
exit 99
SH
chmod +x "$tmp/bin/id" "$tmp/bin/curl" "$tmp/bin/tar"
if output="$(bash "$tmp/repo/scripts/cloud/setup.sh" 2>&1)"; then
    echo 'FAIL: tampered gitleaks archive was accepted'; exit 1
fi
[[ "$output" == *'gitleaks checksum mismatch'* ]] || { echo "FAIL: wrong rejection: $output"; exit 1; }
[[ ! -s "$CALLS" && ! -e "$HOME/.local/bin/gitleaks" ]] || { echo 'FAIL: unverified gitleaks was extracted/installed'; exit 1; }
echo 'PASS: tampered_gitleaks_rejected_before_extraction'

# Non-root agents are allowed to skip apt; the summary must still finish and
# explain a missing native tool. --check remains the strict readiness verdict.
printf '#!/usr/bin/env bash\necho 8.21.2\n' > "$HOME/.local/bin/gitleaks"
chmod +x "$HOME/.local/bin/gitleaks"
rm "$tmp/bin/cmake"
if ! output="$(bash "$tmp/repo/scripts/cloud/setup.sh" 2>&1)"; then
    echo "FAIL: nonroot_native_skip_summary: $output"; exit 1
fi
[[ "$output" == *'SKIPPED: apt native dependencies'* && "$output" == *'cmake: unavailable'* ]] || {
    echo "FAIL: native dependency skip was not explained: $output"; exit 1
}
echo 'PASS: nonroot_native_skip_summary'

# Corepack can create its cache before checking COREPACK_ENABLE_NETWORK=0.
# A readiness check must inspect files without calling either shim, even in summary.
failures=0
printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/cmake"
chmod +x "$tmp/bin/cmake"
for cmd in corepack pnpm; do
    cat > "$tmp/bin/$cmd" <<'SH'
#!/usr/bin/env bash
echo 'SHIM INVOKED' >> "$CALLS"
mkdir -p "$COREPACK_HOME/v1"
echo 9.15.0
SH
done
for cache_state in populated empty; do
    if [[ "$cache_state" == empty ]]; then rm -rf "$COREPACK_HOME"; fi
    : > "$CALLS"
    /usr/bin/find "$HOME" -printf '%p %s %T@\n' | /usr/bin/sort > "$tmp/home-before"
    status=0
    output="$(bash "$tmp/repo/scripts/cloud/setup.sh" --check 2>&1)" || status=$?
    /usr/bin/find "$HOME" -printf '%p %s %T@\n' | /usr/bin/sort > "$tmp/home-after"
    if ! /usr/bin/diff -u "$tmp/home-before" "$tmp/home-after" || [[ -s "$CALLS" ]] ||
       { [[ "$cache_state" == empty ]] && [[ "$status" == 0 || "$output" != *'MISSING: pnpm@9.15.0'* ]]; } ||
       { [[ "$cache_state" == populated ]] && [[ "$status" != 0 ]]; }; then
        echo "FAIL: ${cache_state}_corepack_cache_check_without_home_writes_or_shim_calls: $output"
        failures=$((failures + 1))
    else
        echo "PASS: ${cache_state}_corepack_cache_check_without_home_writes_or_shim_calls"
    fi
done
for cmd in corepack pnpm; do
    printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/$cmd"
done

# Real SHA-256 verification, on both supported architectures. The payload would
# record execution if run as an installer; tar records any premature extraction.
export DOWNLOADS="$tmp/downloads"
# The attacker also replaces the release's checksums asset, so it agrees with the payload.
cat > "$tmp/bin/curl" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$DOWNLOADS"
url="" out=""
while [[ $# -gt 0 ]]; do
    case "$1" in -o) out="$2"; shift ;; https://*) url="$1" ;; esac
    shift
done
[[ -n "$out" ]] || exit 1
payload='#!/usr/bin/env bash\necho UNVERIFIED_EXECUTION >> "$CALLS"\nexit 99\n'
if [[ "$url" == *checksums.txt ]]; then
    sum="$(printf "$payload" | sha256sum | cut -d' ' -f1)"
    printf '%s  gh_2.65.0_linux_amd64.tar.gz\n%s  gh_2.65.0_linux_arm64.tar.gz\n' "$sum" "$sum" > "$out"
else
    printf "$payload" > "$out"
fi
SH
rm "$tmp/bin/uname"
cat > "$tmp/bin/uname" <<'SH'
#!/usr/bin/env bash
case "$1" in -s) echo Linux ;; -m) echo "$TEST_ARCH" ;; esac
SH
chmod +x "$tmp/bin/uname"
for TEST_ARCH in x86_64 aarch64; do
    export TEST_ARCH
    for tool in rustup uv gh; do
        mv "$tmp/bin/$tool" "$tmp/bin/$tool.saved"
        : > "$CALLS"
        : > "$DOWNLOADS"
        status=0
        output="$(bash "$tmp/repo/scripts/cloud/setup.sh" 2>&1)" || status=$?
        mv "$tmp/bin/$tool.saved" "$tmp/bin/$tool"
        if [[ "$tool" == rustup ]]; then
            expected_url="https://static.rust-lang.org/rustup/archive/[0-9.]+/$TEST_ARCH-unknown-linux-gnu/rustup-init"
        elif [[ "$tool" == uv ]]; then
            expected_url="https://github.com/astral-sh/uv/releases/download/[0-9.]+/uv-$TEST_ARCH-unknown-linux-gnu.tar.gz"
        else
            gh_arch=amd64; [[ "$TEST_ARCH" == x86_64 ]] || gh_arch=arm64
            expected_url="https://github.com/cli/cli/releases/download/v[0-9.]+/gh_[0-9.]+_linux_$gh_arch.tar.gz"
        fi
        if [[ "$status" == 0 || "$output" != *"$tool checksum mismatch"* || -s "$CALLS" || -e "$HOME/.local/bin/$tool" ]] ||
           ! grep -Eq "$expected_url " "$DOWNLOADS"; then
            echo "FAIL: tampered_${tool}_rejected_before_execution_or_extraction ($TEST_ARCH): $output"
            cat "$CALLS"
            failures=$((failures + 1))
        else
            echo "PASS: tampered_${tool}_rejected_before_execution_or_extraction ($TEST_ARCH)"
        fi
    done
done
[[ "$failures" == 0 ]]

# A verified rustup-init must not immediately fetch a mutable self-update while
# installing the repository toolchain.
cat > "$tmp/bin/rustup" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == 'toolchain install '* && " $* " != *' --no-self-update '* ]]; then
    echo 'UNVERIFIED SELF-UPDATE' >> "$CALLS"
    exit 99
fi
SH
: > "$CALLS"
if ! output="$(bash "$tmp/repo/scripts/cloud/setup.sh" 2>&1)" || [[ -s "$CALLS" ]]; then
    echo "FAIL: rustup_toolchain_install_disables_self_update: $output"
    cat "$CALLS"
    exit 1
fi
echo 'PASS: rustup_toolchain_install_disables_self_update'
