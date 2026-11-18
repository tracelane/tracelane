#!/usr/bin/env bash
# Shared Linux bootstrap for cloud agents and CI. Run from any directory.
# Downloads and dependency resolution fail CLOSED; --check never installs.
set -euo pipefail
case "${1:-}" in
    '') [[ $# == 0 ]] || { echo 'Usage: setup.sh [--check]' >&2; exit 2; } ;;
    --check) [[ $# == 1 ]] || { echo 'Usage: setup.sh [--check]' >&2; exit 2; } ;;
    *) echo 'Usage: setup.sh [--check]' >&2; exit 2 ;;
esac
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
export PATH="$HOME/.local/bin:${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
rust_channel="$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' rust-toolchain.toml)"
[[ -n "$rust_channel" ]] || { echo 'Missing Rust channel in rust-toolchain.toml' >&2; exit 1; }
pnpm_version=9.15.0
rustup_version=1.28.2
uv_version=0.6.17
gitleaks_version=8.21.2
requirements="$root/scripts/ci/requirements/python-ci.txt"
identity_allowed() {
    local email
    email="$(git config user.email 2>/dev/null || true)"
    [[ -n "$email" && -n "$(git config user.name 2>/dev/null || true)" ]] &&
        awk -v email="$email" '{sub(/#.*/, ""); gsub(/^[ \t]+|[ \t]+$/, ""); if ($0 == email) found=1} END {exit !found}' .githooks/commit-authors.allow
}
# rustup creates RUSTUP_HOME even with RUSTUP_AUTO_INSTALL=0, so --check reads the
# installed toolchain's binaries directly and never invokes rustup.
find_rust_bin() {
    rust_bin=""
    local dir
    for dir in "${RUSTUP_HOME:-$HOME/.rustup}/toolchains/$rust_channel"-*/bin; do
        if [[ -x "$dir/rustc" ]]; then rust_bin="$dir"; return 0; fi
    done
    return 0
}
summary() {
    echo 'Tool versions:'
    "$rust_bin/rustc" --version
    "$rust_bin/cargo" --version
    if command -v cmake >/dev/null; then
        cmake --version | head -n 1
    else
        echo 'cmake: unavailable (native dependencies skipped; run --check for readiness)'
    fi
    node --version
    if [[ "${1:-}" == --check ]]; then
        echo "pnpm@$pnpm_version: cached (corepack/pnpm shims not invoked)"
    else
        corepack --version
        pnpm --version
    fi
    uv --version
    "$root/.venv/bin/python" --version
    "$root/.venv/bin/python" -m pytest --version
    "$root/.venv/bin/ruff" --version
    "$HOME/.local/bin/gitleaks" version
    gh --version | head -n 1
}
if [[ "${1:-}" == --check ]]; then
    # Prevent Rust/corepack shims from silently downloading during inspection.
    export RUSTUP_AUTO_INSTALL=0 COREPACK_ENABLE_NETWORK=0 npm_config_offline=true PYTHONDONTWRITEBYTECODE=1
    missing=()
    for tool in rustup cmake make gcc g++ pkg-config node corepack pnpm uv gh git python3; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
    done
    find_rust_bin
    if [[ -z "$rust_bin" ]] || ! "$rust_bin/rustc" --version >/dev/null 2>&1 ||
       ! "$rust_bin/cargo" --version >/dev/null 2>&1 ||
       ! "$rust_bin/rustfmt" --version >/dev/null 2>&1 ||
       ! "$rust_bin/cargo-clippy" --version >/dev/null 2>&1; then
        missing+=("Rust $rust_channel with rustfmt/clippy")
    fi
    node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' >/dev/null 2>&1 || missing+=('Node >=22')
    # Corepack creates cache directories even with network disabled. Inspect its
    # v1 installation marker and entry point without executing either shim.
    corepack_home="${COREPACK_HOME:-${XDG_CACHE_HOME:-${LOCALAPPDATA:-$HOME/.cache}}/node/corepack}"
    pnpm_cache="$corepack_home/v1/pnpm/$pnpm_version"
    [[ -f "$pnpm_cache/.corepack" && -f "$pnpm_cache/bin/pnpm.cjs" ]] || missing+=("pnpm@$pnpm_version")
    [[ "$("$HOME/.local/bin/gitleaks" version 2>/dev/null || true)" == "$gitleaks_version" ]] || missing+=("gitleaks $gitleaks_version in ~/.local/bin")
    pkg-config --exists openssl >/dev/null 2>&1 || missing+=('libssl-dev (OpenSSL headers)')
    if ! "$root/.venv/bin/python" - "$requirements" <<'PY'
import importlib.metadata as m
import pathlib, re, sys
missing = []
for name, version in re.findall(r'^([\w-]+)==([^\s\\]+)', pathlib.Path(sys.argv[1]).read_text(), re.M):
    try:
        if m.version(name) != version:
            missing.append(f'{name}=={version}')
    except m.PackageNotFoundError:
        missing.append(f'{name}=={version}')
if missing:
    print('Missing Python requirements: ' + ', '.join(missing))
sys.exit(bool(missing))
PY
    then missing+=('hash-pinned Python CI environment (.venv)'); fi
    [[ -f node_modules/.modules.yaml && -x apps/web/node_modules/.bin/tsc ]] || missing+=('pnpm workspace dependencies')
    for artifact in index.js index.d.ts node.js node.d.ts; do
        [[ -f "packages/verifier-typescript/dist/$artifact" ]] || missing+=("audit-verifier build ($artifact)")
    done
    # Inspect cached archives directly: even cargo metadata --offline can unpack
    # crates and write cache locks. A new source kind needs an explicit check.
    if ! python3 - <<'PY_CACHE'
import os, pathlib, tomllib
cache = pathlib.Path(os.environ.get("CARGO_HOME", str(pathlib.Path.home() / ".cargo")))
for package in tomllib.loads(pathlib.Path("Cargo.lock").read_text())["package"]:
    source = package.get("source")
    if not source:
        continue
    name = f"{package['name']}-{package['version']}"
    if source != "registry+https://github.com/rust-lang/crates.io-index":
        raise SystemExit(f"Cannot verify cached source: {source}")
    if not any((cache / "registry/cache").glob(f"*/{name}.crate")):
        raise SystemExit(f"Missing Cargo cache: {name}")
PY_CACHE
    then missing+=('cargo fetch --locked cache'); fi
    [[ "$(git config core.hooksPath 2>/dev/null || true)" == .githooks ]] || missing+=('git core.hooksPath=.githooks')
    identity_allowed || missing+=('allowlisted Git commit identity')
    if (( ${#missing[@]} )); then
        printf 'MISSING: %s\n' "${missing[@]}"
        exit 1
    fi
    summary --check
    echo 'PASS: cloud bootstrap --check'
    exit 0
fi

if command -v apt-get >/dev/null 2>&1 && [[ "$(id -u)" == 0 ]]; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl git python3 cmake build-essential pkg-config libssl-dev
else
    echo 'SKIPPED: apt native dependencies (requires apt-get and root); provide cmake, build-essential, pkg-config, libssl-dev, curl, git and python3 yourself.'
fi
for tool in curl git python3 tar sha256sum; do
    command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }
done
case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) arch=x64; gh_arch=amd64
        target=x86_64-unknown-linux-gnu
        # https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init.sha256
        rustup_sha=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c
        # https://github.com/astral-sh/uv/releases/download/0.6.17/uv-x86_64-unknown-linux-gnu.tar.gz.sha256
        uv_sha=720ec28f7a94aa8cd91d3d57dec1434d64b9ae13d1dd6a25f4c0cdb837ba9cf6
        # https://github.com/cli/cli/releases/download/v2.65.0/gh_2.65.0_checksums.txt
        gh_sha=762569efe785082b7d1feb06995efece1a9cecce16da8503ac6fdbcbea04085b
        node_sha=978978a635eef872fa68beae09f0aad0bbbae6757e444da80b570964a97e62a3
        gitleaks_sha=5bc41815076e6ed6ef8fbecc9d9b75bcae31f39029ceb55da08086315316e3ba ;;
    Linux/aarch64|Linux/arm64) arch=arm64; gh_arch=arm64
        target=aarch64-unknown-linux-gnu
        # https://static.rust-lang.org/rustup/archive/1.28.2/aarch64-unknown-linux-gnu/rustup-init.sha256
        rustup_sha=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c
        # https://github.com/astral-sh/uv/releases/download/0.6.17/uv-aarch64-unknown-linux-gnu.tar.gz.sha256
        uv_sha=6fb716c36e8ca9cf98b7cb347b0ced41679145837eb22890ee5fa9d8b68ce9f5
        # https://github.com/cli/cli/releases/download/v2.65.0/gh_2.65.0_checksums.txt
        gh_sha=8bcec9f3ee5c7c3700359a75da774c71221064a0ba017537795aa32ac8bbb481
        node_sha=b2f3a96f31486bfc365192ad65ced14833ad2a3c2e1bcefec4846902f264fa28
        gitleaks_sha=654c935542c89f565aabe7bf7c6c500830f116c114f0aeb509d2460c1ac2e6da ;;
    *) echo 'Unsupported platform: cloud setup requires Linux x86_64 or arm64.' >&2; exit 1 ;;
esac
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$HOME/.local/bin"
fetch() { curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 15 --max-time 300 "$1" -o "$2"; }
verify() { printf '%s  %s\n' "$1" "$2" | sha256sum --check --status; }

if ! command -v rustup >/dev/null; then
    fetch "https://static.rust-lang.org/rustup/archive/$rustup_version/$target/rustup-init" "$tmp/rustup-init"
    verify "$rustup_sha" "$tmp/rustup-init" || { echo 'rustup checksum mismatch' >&2; exit 1; }
    chmod +x "$tmp/rustup-init"
    "$tmp/rustup-init" -y --no-modify-path --profile minimal --default-toolchain none
fi
mapfile -t components < <(python3 -c 'import tomllib; print("\n".join(tomllib.load(open("rust-toolchain.toml", "rb"))["toolchain"].get("components", [])))')
rust_args=()
for component in "${components[@]}"; do [[ -z "$component" ]] || rust_args+=(--component "$component"); done
# Keep the verified installer pin: toolchain installation must not self-update rustup.
rustup toolchain install "$rust_channel" --no-self-update --profile minimal "${rust_args[@]}"

# Ubuntu 24.04 apt provides Node 18; the workspace requires >=22. The Node
# distribution includes corepack. Checksums: nodejs.org/dist/v22.22.2/SHASUMS256.txt.
if ! node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' >/dev/null 2>&1 || ! command -v corepack >/dev/null; then
    node_release="node-v22.22.2-linux-$arch"
    fetch "https://nodejs.org/dist/v22.22.2/$node_release.tar.gz" "$tmp/node.tar.gz"
    verify "$node_sha" "$tmp/node.tar.gz" || { echo 'Node checksum mismatch' >&2; exit 1; }
    mkdir -p "$HOME/.local/lib"
    tar -xzf "$tmp/node.tar.gz" -C "$HOME/.local/lib"
    for tool in node npm npx corepack; do
        ln -sf "$HOME/.local/lib/$node_release/bin/$tool" "$HOME/.local/bin/$tool"
    done
fi
corepack enable --install-directory "$HOME/.local/bin"
corepack prepare "pnpm@$pnpm_version" --activate
pnpm install --frozen-lockfile
# Web imports the verifier through its dist exports; a frozen install alone is
# insufficient for typecheck in a fresh checkout (same prerequisite as CI).
pnpm --filter @tracelanedev/audit-verifier build

if ! command -v uv >/dev/null; then
    fetch "https://github.com/astral-sh/uv/releases/download/$uv_version/uv-$target.tar.gz" "$tmp/uv.tar.gz"
    verify "$uv_sha" "$tmp/uv.tar.gz" || { echo 'uv checksum mismatch' >&2; exit 1; }
    tar -xzf "$tmp/uv.tar.gz" -C "$tmp" "uv-$target/uv" "uv-$target/uvx"
    install -m 0755 "$tmp/uv-$target/uv" "$tmp/uv-$target/uvx" "$HOME/.local/bin/"
fi
if [[ ! -x .venv/bin/python ]]; then uv venv --python 3.12 .venv; fi
uv pip sync --python .venv/bin/python --require-hashes "$requirements"

# Pinned against the release's gitleaks_8.21.2_checksums.txt, checked BEFORE extraction.
if [[ "$("$HOME/.local/bin/gitleaks" version 2>/dev/null || true)" != "$gitleaks_version" ]]; then
    fetch "https://github.com/gitleaks/gitleaks/releases/download/v$gitleaks_version/gitleaks_${gitleaks_version}_linux_$arch.tar.gz" "$tmp/gitleaks.tar.gz"
    verify "$gitleaks_sha" "$tmp/gitleaks.tar.gz" || { echo 'gitleaks checksum mismatch' >&2; exit 1; }
    tar -xzf "$tmp/gitleaks.tar.gz" -C "$tmp" gitleaks
    install -m 0755 "$tmp/gitleaks" "$HOME/.local/bin/gitleaks"
fi
if ! command -v gh >/dev/null; then
    if command -v apt-get >/dev/null && [[ "$(id -u)" == 0 ]]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gh
    else
        gh_version=2.65.0
        gh_release="gh_${gh_version}_linux_$gh_arch"
        fetch "https://github.com/cli/cli/releases/download/v$gh_version/$gh_release.tar.gz" "$tmp/$gh_release.tar.gz"
        # Pinned hash: a checksums asset fetched beside the archive can be replaced with it.
        verify "$gh_sha" "$tmp/$gh_release.tar.gz" || { echo 'gh checksum mismatch' >&2; exit 1; }
        tar -xzf "$tmp/$gh_release.tar.gz" -C "$tmp" "$gh_release/bin/gh"
        install -m 0755 "$tmp/$gh_release/bin/gh" "$HOME/.local/bin/gh"
    fi
fi
git config --local core.hooksPath .githooks
if ! identity_allowed; then
    git config --local user.email 230745913+Sanjeevlabs@users.noreply.github.com
    git config --local user.name Sanjeev
fi
rustup run "$rust_channel" cargo fetch --locked
find_rust_bin
summary
echo 'Bootstrap complete. For subsequent shells: export PATH="$HOME/.local/bin:${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"'
echo 'Python CI tools: uv run --no-sync --python .venv/bin/python <command>'
