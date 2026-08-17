/**
 * The version this server reports as MCP `serverInfo.version`.
 *
 * Kept as a source constant rather than a `require("../package.json")`
 * so `tsc --noEmit` stays inside `rootDir` and the published bundle does
 * not carry the dev-dependency list. It is NOT trusted to stay in sync by
 * convention: `scripts/check-registry-manifest.mjs --check` fails the
 * build when it drifts from `package.json`, and `--selftest` proves that
 * check blocks.
 *
 * It was hardcoded at "0.1.0" while the package moved on, so every MCP
 * client displayed a version that had not existed for two releases.
 */
export const MCP_SERVER_VERSION = "0.2.4";
