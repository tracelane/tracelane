#!/usr/bin/env node
/**
 * Verify `server.json` (MCP registry manifest) agrees with `package.json`.
 *
 * WHY. The registry's npm ownership check fetches
 * `registry.npmjs.org/<identifier>/<version>` and demands the published
 * `package.json` carry `"mcpName"` EQUAL to `server.json`'s `name`
 * (registry `internal/validators/registries/npm.go:90,94`). Three fields
 * therefore have to move together — server name, `mcpName`, and the npm
 * version — and nothing but this check couples them. Drift does not
 * degrade gracefully: `mcp-publisher publish` rejects the submission, and
 * that failure lands in a tagged release run, after npm has already
 * published.
 *
 * Modes: `--check` (default) · `--selftest` (proves --check BLOCKS).
 * Fails CLOSED — unreadable or unparseable input is a failure.
 */

import { readFileSync } from "node:fs";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(HERE, "..");

/** Registry-enforced ceiling on `description` (server.schema.json). */
const DESCRIPTION_MAX = 100;
const NPM_REGISTRY_BASE_URL = "https://registry.npmjs.org";
const SCHEMA_URL_RE =
	/^https:\/\/static\.modelcontextprotocol\.io\/schemas\/[A-Za-z0-9_~.-]+\/server\.schema\.json$/;

/**
 * @returns {string[]} the list of violations; empty means OK.
 */
export function violations(pkgPath, serverPath, versionTsPath) {
	/** @type {string[]} */
	const bad = [];
	let pkg;
	let srv;
	try {
		pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
	} catch (err) {
		return [`package.json unreadable/unparseable: ${err.message}`];
	}
	try {
		srv = JSON.parse(readFileSync(serverPath, "utf8"));
	} catch (err) {
		return [`server.json unreadable/unparseable: ${err.message}`];
	}

	if (!pkg.mcpName) {
		bad.push(
			'package.json is missing "mcpName" — the registry cannot verify npm ownership without it',
		);
	} else if (pkg.mcpName !== srv.name) {
		bad.push(
			`package.json mcpName "${pkg.mcpName}" != server.json name "${srv.name}" — registry ownership validation will reject the publish`,
		);
	}

	if (srv.version !== pkg.version) {
		bad.push(
			`server.json version "${srv.version}" != package.json version "${pkg.version}"`,
		);
	}

	// The registry resolves `$schema` to an embedded schema file by version
	// segment and errors on a version it does not carry
	// (registry internal/validators/schema.go:37-43). A missing or malformed
	// URL is a hard reject, not a default.
	if (!SCHEMA_URL_RE.test(srv.$schema ?? "")) {
		bad.push(
			`server.json $schema must be https://static.modelcontextprotocol.io/schemas/<version>/server.schema.json (got "${srv.$schema ?? "<absent>"}")`,
		);
	}

	if (typeof srv.description !== "string" || srv.description.length === 0) {
		bad.push("server.json description is missing");
	} else if (srv.description.length > DESCRIPTION_MAX) {
		bad.push(
			`server.json description is ${srv.description.length} chars (registry max ${DESCRIPTION_MAX})`,
		);
	}

	const npmPkgs = (srv.packages ?? []).filter((p) => p.registryType === "npm");
	if (npmPkgs.length !== 1) {
		bad.push(
			`server.json must declare exactly one npm package, found ${npmPkgs.length}`,
		);
	}
	for (const p of npmPkgs) {
		if (p.identifier !== pkg.name) {
			bad.push(
				`server.json npm identifier "${p.identifier}" != package.json name "${pkg.name}"`,
			);
		}
		if (p.version !== pkg.version) {
			bad.push(
				`server.json npm package version "${p.version}" != package.json version "${pkg.version}"`,
			);
		}
		if (p.registryBaseUrl !== NPM_REGISTRY_BASE_URL) {
			bad.push(
				`server.json npm registryBaseUrl must be exactly "${NPM_REGISTRY_BASE_URL}" (got "${p.registryBaseUrl}")`,
			);
		}
		if (p.transport?.type !== "stdio") {
			bad.push(
				`server.json npm transport.type must be "stdio" (got "${p.transport?.type}") — that is the transport npx serves by default`,
			);
		}
	}

	if (!pkg.bin || Object.keys(pkg.bin).length === 0) {
		bad.push(
			"package.json declares no bin — `npx @tracelanedev/mcp` has nothing to execute",
		);
	}

	// MCP `serverInfo.version` is what every connected client displays. It
	// sat at "0.1.0" through two releases because nothing coupled it.
	if (versionTsPath) {
		let versionTs;
		try {
			versionTs = readFileSync(versionTsPath, "utf8");
		} catch (err) {
			return [...bad, `src/version.ts unreadable: ${err.message}`];
		}
		const m = versionTs.match(
			/export const MCP_SERVER_VERSION\s*=\s*["']([^"']+)["']/,
		);
		if (!m) {
			bad.push(
				"src/version.ts does not export a string MCP_SERVER_VERSION constant",
			);
		} else if (m[1] !== pkg.version) {
			bad.push(
				`src/version.ts MCP_SERVER_VERSION "${m[1]}" != package.json version "${pkg.version}" — MCP clients would show a version that is not the one they installed`,
			);
		}
	}

	return bad;
}

function selftest() {
	const scratch = mkdtempSync(join(tmpdir(), "mcp-registry-selftest-"));
	let failures = 0;
	const basePkg = JSON.parse(
		readFileSync(join(PKG_ROOT, "package.json"), "utf8"),
	);
	const baseSrv = JSON.parse(
		readFileSync(join(PKG_ROOT, "server.json"), "utf8"),
	);

	const baseVersionTs = readFileSync(
		join(PKG_ROOT, "src", "version.ts"),
		"utf8",
	);

	const run = (name, mutate, shouldBlock) => {
		const pkg = structuredClone(basePkg);
		const srv = structuredClone(baseSrv);
		const box = { versionTs: baseVersionTs };
		mutate(pkg, srv, box);
		const p = join(scratch, "package.json");
		const s = join(scratch, "server.json");
		const v = join(scratch, "version.ts");
		writeFileSync(p, JSON.stringify(pkg));
		writeFileSync(s, JSON.stringify(srv));
		writeFileSync(v, box.versionTs);
		const bad = violations(p, s, v);
		const blocked = bad.length > 0;
		if (blocked === shouldBlock) {
			console.log(
				`  PASS  ${name} — ${blocked ? `BLOCKED: ${bad[0]}` : "allowed"}`,
			);
		} else {
			failures += 1;
			console.error(
				`  FAIL  ${name} — expected ${shouldBlock ? "BLOCK" : "ALLOW"}, got ${
					blocked ? `BLOCK (${bad.join("; ")})` : "ALLOW"
				}`,
			);
		}
	};

	try {
		// POSITIVE first: the committed pair must pass, or every negative
		// below proves nothing (an always-red gate blocks everything).
		run("committed package.json + server.json", () => {}, false);

		run(
			"mcpName missing",
			(pkg) => {
				pkg.mcpName = undefined;
			},
			true,
		);
		run(
			"mcpName != server name",
			(pkg) => {
				pkg.mcpName = "io.github.someoneelse/tracelane-mcp";
			},
			true,
		);
		run(
			"npm version bumped, server.json left behind",
			(pkg) => {
				pkg.version = "9.9.9";
			},
			true,
		);
		run(
			"server.json package entry pins a different version",
			(_pkg, srv) => {
				srv.packages[0].version = "0.0.1";
			},
			true,
		);
		run(
			"server.json points at the wrong npm package",
			(_pkg, srv) => {
				srv.packages[0].identifier = "@someoneelse/mcp";
			},
			true,
		);
		run(
			"registryBaseUrl not the public npm registry",
			(_pkg, srv) => {
				srv.packages[0].registryBaseUrl = "https://npm.pkg.github.com";
			},
			true,
		);
		run(
			"description exceeds the registry 100-char ceiling",
			(_pkg, srv) => {
				srv.description = "x".repeat(101);
			},
			true,
		);
		run(
			"bin removed — nothing for npx to execute",
			(pkg) => {
				pkg.bin = undefined;
			},
			true,
		);
		run(
			"$schema dropped",
			(_pkg, srv) => {
				srv.$schema = undefined;
			},
			true,
		);
		run(
			"$schema points somewhere other than the MCP schema host",
			(_pkg, srv) => {
				srv.$schema = "https://example.com/server.schema.json";
			},
			true,
		);
		run(
			"src/version.ts left at the old release",
			(_pkg, _srv, box) => {
				box.versionTs = 'export const MCP_SERVER_VERSION = "0.1.0";\n';
			},
			true,
		);
		run(
			"src/version.ts no longer exports the constant",
			(_pkg, _srv, box) => {
				box.versionTs = "export const SOMETHING_ELSE = 1;\n";
			},
			true,
		);
	} finally {
		rmSync(scratch, { recursive: true, force: true });
	}

	if (failures > 0) {
		console.error(`\nselftest FAILED (${failures} case(s))`);
		process.exit(1);
	}
	console.log(
		"\nselftest OK — --check blocks on every server.json/package.json drift",
	);
}

const mode = process.argv[2] ?? "--check";
if (mode === "--selftest") {
	selftest();
} else if (mode === "--check") {
	const bad = violations(
		join(PKG_ROOT, "package.json"),
		join(PKG_ROOT, "server.json"),
		join(PKG_ROOT, "src", "version.ts"),
	);
	if (bad.length > 0) {
		console.error("MCP registry manifest check FAILED:");
		for (const b of bad) console.error(`  · ${b}`);
		process.exit(1);
	}
	console.log("server.json and package.json agree");
} else {
	console.error(`unknown mode "${mode}" (--check | --selftest)`);
	process.exit(2);
}
