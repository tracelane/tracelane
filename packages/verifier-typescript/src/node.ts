import { readFileSync } from "node:fs";
import {
	type VerifyOptions,
	type VerifyReport,
	verifyLedgerText,
} from "./index.js";

/**
 * Verify an audit ledger from a FILE path (Node only). The package root
 * (`@tracelanedev/audit-verifier`) stays free of `node:fs` so `verifyLedgerText`
 * bundles for the browser / the dashboard; this `/node` entry is the filesystem
 * convenience wrapper for the CLI and Node callers.
 */
export async function verifyLedger(
	path: string,
	options: VerifyOptions = {},
): Promise<VerifyReport> {
	return verifyLedgerText(readFileSync(path, "utf-8"), {
		...options,
		label: path,
	});
}
