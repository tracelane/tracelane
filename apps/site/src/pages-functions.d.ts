/**
 * Ambient type declarations for Cloudflare Pages Functions.
 *
 * Cloudflare Pages exposes a PagesFunction generic for request handlers.
 * @cloudflare/workers-types covers Workers but not Pages-specific types,
 * so we define them here.
 */

interface EventContext<Env, P extends string, Data> {
  request: Request;
  env: Env;
  params: Record<P, string>;
  data: Data;
  next: (input?: Request | string, init?: RequestInit) => Promise<Response>;
  waitUntil: (promise: Promise<unknown>) => void;
  passThroughOnException: () => void;
}

type PagesFunction<
  Env = Record<string, unknown>,
  P extends string = string,
  Data extends Record<string, unknown> = Record<string, unknown>,
> = (context: EventContext<Env, P, Data>) => Response | Promise<Response>;
