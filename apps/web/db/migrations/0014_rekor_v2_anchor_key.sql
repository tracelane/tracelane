-- Migration 0014 — ADR-062: public Rekor v2 anchoring via a dedicated per-tenant
-- ECDSA-P256 "anchor key". Rekor v2's hashedrekord verifier only accepts ECDSA /
-- RSA / Ed25519ph (pkg/types/hashedrekord/hashedrekord.go loads WithED25519ph),
-- so our pure-Ed25519 signing key (ADR-057) cannot sign the transparency-log
-- entry. The two-key model keeps Ed25519 for the local attestation (untouched)
-- and adds a single-purpose ECDSA-P256 key that signs the Merkle root submitted
-- to log2025-1.rekor.sigstore.dev.
--
-- Anchor-key columns live ON tenant_audit_keys (1:1 with the tenant audit
-- identity, same ByokMasterKey protection class). Both nullable: the ECDSA key is
-- lazily minted on first anchor, mirroring the Ed25519 mint. Idempotent per the
-- Neon-drift rule (0011 lesson): ADD COLUMN IF NOT EXISTS.

ALTER TABLE tenant_audit_keys
  ADD COLUMN IF NOT EXISTS encrypted_anchor_key text;
--> statement-breakpoint
-- ECDSA-P256 public key in SubjectPublicKeyInfo (DER) form, base64. This is the
-- `verifier.publicKey.rawBytes` submitted to Rekor and the pin the verifier
-- checks the anchor entry's embedded pubkey against (H1-style, outside the
-- ClickHouse blast radius — mirrors public_key_b64 for the Ed25519 key).
ALTER TABLE tenant_audit_keys
  ADD COLUMN IF NOT EXISTS anchor_pubkey_spki_b64 text;
