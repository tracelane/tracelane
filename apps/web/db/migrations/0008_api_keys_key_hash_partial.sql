DROP INDEX "api_keys_key_hash_idx";--> statement-breakpoint
CREATE UNIQUE INDEX "api_keys_key_hash_idx" ON "api_keys" USING btree ("key_hash") WHERE "api_keys"."key_hash" IS NOT NULL;