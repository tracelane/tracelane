/**
 * ClickHouse client singleton for the MCP server.
 *
 * Reads connection config from env vars with localhost defaults so the
 * MCP server works out-of-box against the docker-compose dev stack.
 * All queries MUST use parameter binding — never string interpolation.
 */

import { createClient } from "@clickhouse/client";

let _client: ReturnType<typeof createClient> | undefined;

export function getDb() {
	if (!_client) {
		_client = createClient({
			url: process.env.CLICKHOUSE_URL ?? "http://localhost:8123",
			username: process.env.CLICKHOUSE_USER ?? "default",
			password: process.env.CLICKHOUSE_PASSWORD ?? "",
			database: process.env.CLICKHOUSE_DB ?? "tracelane",
		});
	}
	return _client;
}
