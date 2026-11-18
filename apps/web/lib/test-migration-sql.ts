/**
 * Test-only: make a migration file runnable on a throwaway PGlite/Postgres test database.
 *
 * Production applies each `CONCURRENTLY` migration on its own, outside a transaction
 * (scripts/deploy/migrate.sh). A test harness runs a whole file through one `exec`, which is one
 * implicit transaction, where CONCURRENTLY is an error. So test databases build those indexes
 * plainly — the same rewrite the gateway's test harness makes (crates/gateway/src/db/mod.rs,
 * `apply_migrations`). Every loader of apps/web/db/migrations in a test goes through this.
 */
export function migrationSqlForTestDb(sql: string): string {
	return sql
		.replaceAll("CREATE INDEX CONCURRENTLY", "CREATE INDEX")
		.replaceAll("CREATE UNIQUE INDEX CONCURRENTLY", "CREATE UNIQUE INDEX");
}
