/**
 * OpenNext → Cloudflare adapter config (apps/web Vercel→CF migration).
 *
 * `defineCloudflareConfig()` with defaults runs the whole Next.js app — routes
 * AND middleware — in a single Cloudflare Worker under `nodejs_compat` (NOT the
 * V8-isolate edge runtime). That is why no route needs `export const runtime`
 * changes: everything stays on the Node runtime it already uses, and
 * `node:crypto` / WorkOS AuthKit JWT verification keep working.
 *
 * Caveats tracked for the migration:
 *   - `@node-rs/argon2` is a native `.node` addon and does NOT run on Workers
 *     even with nodejs_compat. The api-keys mint route must move to a WASM
 *     argon2 or delegate hashing to the gateway before that route works on CF.
 *   - No incremental cache / R2 binding wired yet (defaults to in-worker). Add
 *     `incrementalCache` here if/when we want KV/R2-backed ISR.
 */
import { defineCloudflareConfig } from "@opennextjs/cloudflare";

export default defineCloudflareConfig();
