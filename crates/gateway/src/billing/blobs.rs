//! BILL-01 / ADR-076 §2.3 — read-side rehydration of content-addressed blobs.
//!
//! Ingest replaces any oversized attribute value with `{"$ref":"blake3:<hex>"}`
//! (`crates/ingest/src/clickhouse_writer.rs`, `substitute_blobs`) before storing
//! a span's `attributes`. Every gateway read that returns span content to a
//! customer or a consumer must reverse that substitution — otherwise a
//! deduplicated system prompt or message array reads back as a bare `$ref`
//! object, which is meaningless to anyone outside this file.
//!
//! # Amplification budget (spec §2.5b)
//!
//! ONE query per call: every `$ref` found across every span passed in is
//! collected into a single `SELECT hash, bytes FROM blobs WHERE tenant_id = ?
//! AND hex(hash) IN (?, ?, …)` — never one query per span, never one per ref.
//! Two spans sharing the identical blob cost exactly one hash in that list.
//!
//! # Fail-open (a read path, CLAUDE.md §10)
//!
//! A missing blob (GC raced the read, or the row never landed — a blob insert
//! is best-effort on the write side) renders `{"$ref":…, "missing": true}`
//! rather than an error or a panic. A ClickHouse failure on the lookup itself
//! leaves every `$ref` exactly as stored (still valid JSON, just unexpanded)
//! and returns `Ok(())` — the trace still renders, degraded rather than down.

use std::collections::{HashMap, HashSet};

use tracelane_shared::TenantId;

/// The `blake3:` prefix every substituted ref carries (ingest's own
/// `substitute_blobs`, mirrored).
const REF_PREFIX: &str = "blake3:";

/// Distinguishes an ALREADY-substituted `$ref` object from real content.
/// Mirrors `crates/ingest/src/clickhouse_writer.rs::is_blob_ref` exactly —
/// same shape, same prefix — but kept as an independent copy rather than a
/// shared crate function: this is the read side of a write-side contract, not
/// shared logic, and `crates/ingest` is not a dependency of `crates/gateway`.
fn as_blob_ref(v: &serde_json::Value) -> Option<[u8; 32]> {
    let hex_str = v
        .as_object()?
        .get("$ref")?
        .as_str()?
        .strip_prefix(REF_PREFIX)?;
    let bytes = hex::decode(hex_str).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

/// Recursively collect every distinct blob hash referenced anywhere in `v`.
/// Refs are always a whole JSON value at some level (an attribute's value, or
/// — for an already-extracted `JSONExtractRaw` string re-parsed as JSON — the
/// top-level value itself), never a partial string, so a depth-first walk
/// that stops descending the instant it finds a ref is enough; it can never
/// find "one ref nested inside another" because a ref replaces the ENTIRE
/// value it stood in for.
fn collect_refs(v: &serde_json::Value, out: &mut Vec<[u8; 32]>) {
    if let Some(hash) = as_blob_ref(v) {
        out.push(hash);
        return;
    }
    match v {
        serde_json::Value::Object(m) => {
            for val in m.values() {
                collect_refs(val, out);
            }
        }
        serde_json::Value::Array(a) => {
            for val in a {
                collect_refs(val, out);
            }
        }
        _ => {}
    }
}

/// Substitute every ref found in `v` with the looked-up content (or a
/// `missing: true` marker) from `blobs`. Mirrors [`collect_refs`]'s walk.
fn substitute_refs(v: &mut serde_json::Value, blobs: &HashMap<[u8; 32], String>) {
    if let Some(hash) = as_blob_ref(v) {
        *v = match blobs.get(&hash) {
            Some(bytes) => serde_json::from_str(bytes)
                .unwrap_or_else(|_| serde_json::Value::String(bytes.clone())),
            None => {
                let ref_val = v
                    .as_object()
                    .and_then(|m| m.get("$ref"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                serde_json::json!({ "$ref": ref_val, "missing": true })
            }
        };
        return;
    }
    match v {
        serde_json::Value::Object(m) => {
            for val in m.values_mut() {
                substitute_refs(val, blobs);
            }
        }
        serde_json::Value::Array(a) => {
            for val in a.iter_mut() {
                substitute_refs(val, blobs);
            }
        }
        _ => {}
    }
}

#[derive(serde::Deserialize, clickhouse::Row)]
struct BlobLookupRow {
    hash_hex: String,
    bytes: String,
}

/// Fetch every blob named in `hashes` for `tenant`, in ONE query. `hex(hash)`
/// (comparing `String` to `String`) rather than binding raw `[u8; 32]` query
/// PARAMETERS — the RowBinary type-matching rule (B-274) binds an INSERT
/// struct's field to a column type; a bound query PARAMETER is a different
/// wire path (ClickHouse's own value-substitution), and comparing text avoids
/// relying on that path accepting a raw byte-array bind at all.
async fn fetch_blobs(
    client: &clickhouse::Client,
    tenant: &TenantId,
    hashes: &[[u8; 32]],
) -> anyhow::Result<HashMap<[u8; 32], String>> {
    if hashes.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = vec!["?"; hashes.len()].join(", ");
    let sql = crate::clickhouse_query::TenantQuery::new(
        format!(
            "SELECT hex(hash) AS hash_hex, bytes FROM tracelane.blobs \
             WHERE tenant_id = ? AND hex(hash) IN ({placeholders})"
        ),
        // Rehydration always runs for a request already resolved against the
        // tenant's own tier by its caller (the four read routes); this lookup
        // is small (bounded by DISTINCT refs on one page of spans) and never
        // itself the expensive part, so `ceiling()`'s Business-class cap is a
        // deliberately generous, tenant-agnostic bound rather than re-deriving
        // the caller's tier for one auxiliary query.
        crate::clickhouse_query::PlanTier::Business,
    )
    .with_log_comment(format!("tenant_id={tenant}"))
    .sql_with_settings();

    let mut q = client.query(&sql).bind(tenant.to_string());
    for h in hashes {
        // ClickHouse `hex()` emits UPPERCASE. `hex::encode` emits lowercase,
        // and `IN` compares strings byte-for-byte — so the lowercase bind
        // matched ZERO rows on prod and every `$ref` came back `missing:true`
        // (B-393, found by the BILL-01 prod proof, not by the gate: the
        // integration test below was `#[ignore]`d and not yet wired into
        // `run-clickhouse-integration.sh`).
        q = q.bind(hex::encode_upper(h));
    }
    let rows: Vec<BlobLookupRow> = q.fetch_all().await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let mut buf = [0u8; 32];
            let decoded = hex::decode(&r.hash_hex).ok()?;
            if decoded.len() != 32 {
                return None;
            }
            buf.copy_from_slice(&decoded);
            Some((buf, r.bytes))
        })
        .collect())
}

/// Rehydrate every `{"$ref":"blake3:<hex>"}` found in `jsons` (each a raw
/// JSON string — either a whole span's `attributes` column, or an already
/// `JSONExtractRaw`-extracted single value; both shapes are handled
/// uniformly, see the module doc) in place, with ONE ClickHouse query
/// covering every DISTINCT hash across the whole slice.
///
/// A string that fails to parse as JSON is left byte-for-byte unchanged
/// (defensive; every caller's rows already came from a JSON column/expression
/// so this should not occur in practice).
///
/// # Errors
/// Propagates a ClickHouse failure on the lookup query — the caller
/// (`trace_reads.rs`, `dataset_routes.rs`, `trace_share.rs`, `prompt_eval.rs`)
/// treats this as fail-OPEN per CLAUDE.md §10 (a read path): every `$ref` is
/// simply left unexpanded, never turned into a 500.
pub async fn rehydrate(
    client: &clickhouse::Client,
    tenant: &TenantId,
    jsons: &mut [&mut String],
) -> anyhow::Result<()> {
    if jsons.is_empty() {
        return Ok(());
    }
    let mut parsed: Vec<Option<serde_json::Value>> =
        jsons.iter().map(|s| serde_json::from_str(s).ok()).collect();

    let mut hashes: Vec<[u8; 32]> = Vec::new();
    for v in parsed.iter().flatten() {
        collect_refs(v, &mut hashes);
    }
    let distinct: Vec<[u8; 32]> = {
        let mut seen = HashSet::new();
        hashes.into_iter().filter(|h| seen.insert(*h)).collect()
    };
    if distinct.is_empty() {
        return Ok(());
    }

    let blobs = fetch_blobs(client, tenant, &distinct).await?;

    for (slot, v) in jsons.iter_mut().zip(parsed.iter_mut()) {
        let Some(v) = v else { continue };
        substitute_refs(v, &blobs);
        if let Ok(text) = serde_json::to_string(v) {
            **slot = text;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ref_json(hash: [u8; 32]) -> serde_json::Value {
        serde_json::json!({ "$ref": format!("blake3:{}", hex::encode(hash)) })
    }

    #[test]
    fn as_blob_ref_round_trips_a_valid_ref() {
        let hash = [7u8; 32];
        let v = ref_json(hash);
        assert_eq!(as_blob_ref(&v), Some(hash));
    }

    #[test]
    fn as_blob_ref_rejects_real_content() {
        assert_eq!(
            as_blob_ref(&serde_json::json!("just a normal string")),
            None
        );
        assert_eq!(as_blob_ref(&serde_json::json!({"role": "system"})), None);
        assert_eq!(
            as_blob_ref(&serde_json::json!({"$ref": "not-blake3:abc"})),
            None
        );
    }

    #[test]
    fn collect_refs_finds_a_ref_nested_inside_an_attributes_object() {
        let hash = [1u8; 32];
        let attrs = serde_json::json!({
            "gen_ai_system_instructions": ref_json(hash),
            "gen_ai_conversation_id": "conv-1",
        });
        let mut out = Vec::new();
        collect_refs(&attrs, &mut out);
        assert_eq!(out, vec![hash]);
    }

    #[test]
    fn collect_refs_finds_a_bare_top_level_ref() {
        // The dataset_routes.rs / prompt_eval.rs shape: JSONExtractRaw already
        // pulled OUT the single value, which may itself BE the ref.
        let hash = [2u8; 32];
        let mut out = Vec::new();
        collect_refs(&ref_json(hash), &mut out);
        assert_eq!(out, vec![hash]);
    }

    #[test]
    fn collect_refs_deduplicates_across_two_occurrences() {
        let hash = [3u8; 32];
        let attrs = serde_json::json!({
            "a": ref_json(hash),
            "b": ref_json(hash),
        });
        let mut out = Vec::new();
        collect_refs(&attrs, &mut out);
        // collect_refs itself does not dedupe (that is `rehydrate`'s job over
        // the WHOLE slice) — assert the raw count here, dedup separately.
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], hash);
        assert_eq!(out[1], hash);
    }

    #[test]
    fn substitute_refs_fills_in_looked_up_content() {
        let hash = [4u8; 32];
        let mut attrs = serde_json::json!({ "gen_ai_system_instructions": ref_json(hash) });
        let mut blobs = HashMap::new();
        blobs.insert(hash, "\"the real system prompt\"".to_string());
        substitute_refs(&mut attrs, &blobs);
        assert_eq!(
            attrs["gen_ai_system_instructions"],
            "the real system prompt"
        );
    }

    #[test]
    fn substitute_refs_marks_a_missing_blob_rather_than_erroring() {
        let hash = [5u8; 32];
        let mut attrs = serde_json::json!({ "gen_ai_system_instructions": ref_json(hash) });
        substitute_refs(&mut attrs, &HashMap::new());
        assert_eq!(attrs["gen_ai_system_instructions"]["missing"], true);
        assert!(
            attrs["gen_ai_system_instructions"]["$ref"]
                .as_str()
                .unwrap()
                .starts_with("blake3:")
        );
    }

    #[test]
    fn substitute_refs_leaves_ordinary_content_untouched() {
        let mut attrs = serde_json::json!({ "gen_ai_conversation_id": "conv-1" });
        let before = attrs.clone();
        substitute_refs(&mut attrs, &HashMap::new());
        assert_eq!(attrs, before);
    }

    /// The amplification-budget property (spec §2.5b): two spans sharing the
    /// IDENTICAL blob must collapse to exactly ONE hash in the lookup —
    /// `rehydrate`'s own dedup step, reproduced here without any ClickHouse
    /// I/O so the property is provable on every `cargo test`.
    #[test]
    fn two_spans_one_shared_ref_dedupes_to_exactly_one_hash() {
        let shared = [9u8; 32];
        let span_a = serde_json::to_string(&serde_json::json!({
            "gen_ai_system_instructions": ref_json(shared),
        }))
        .unwrap();
        let span_b = serde_json::to_string(&serde_json::json!({
            "gen_ai_system_instructions": ref_json(shared),
            "gen_ai_conversation_id": "conv-2",
        }))
        .unwrap();

        let parsed: Vec<serde_json::Value> = [&span_a, &span_b]
            .iter()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        let mut hashes = Vec::new();
        for v in &parsed {
            collect_refs(v, &mut hashes);
        }
        let distinct: HashSet<[u8; 32]> = hashes.into_iter().collect();
        assert_eq!(
            distinct.len(),
            1,
            "two spans referencing the SAME blob must query it exactly once"
        );
        assert!(distinct.contains(&shared));
    }

    /// Two spans with DIFFERENT blobs must still each resolve correctly —
    /// dedup must never collapse distinct content.
    #[test]
    fn two_different_refs_both_resolve_independently() {
        let (hash_a, hash_b) = ([10u8; 32], [11u8; 32]);
        let mut attrs_a = ref_json(hash_a);
        let mut attrs_b = ref_json(hash_b);
        let mut blobs = HashMap::new();
        blobs.insert(hash_a, "\"prompt A\"".to_string());
        blobs.insert(hash_b, "\"prompt B\"".to_string());
        substitute_refs(&mut attrs_a, &blobs);
        substitute_refs(&mut attrs_b, &blobs);
        assert_eq!(attrs_a, "prompt A");
        assert_eq!(attrs_b, "prompt B");
    }

    /// End-to-end against a REAL ClickHouse (not wiremock — a SELECT's
    /// RowBinary response cannot be hand-mocked meaningfully). Matches the
    /// established convention in this tree
    /// (`retention_sweep.rs::enforce_delete_is_accepted_by_the_server_for_every_content_table`):
    /// `#[ignore]`d by default, run via `scripts/ci/run-clickhouse-integration.sh`.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn rehydrate_against_a_real_clickhouse_fills_in_and_marks_missing() {
        let Ok(url) = std::env::var("CLICKHOUSE_TEST_URL") else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let root = clickhouse::Client::default().with_url(&url);
        root.query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .expect("create database");
        let ch = clickhouse::Client::default()
            .with_url(&url)
            .with_database("tracelane");
        for stmt in crate::clickhouse_query::split_migration_statements(include_str!(
            "../../../../infra/dev/clickhouse/migrations/24_bill01_meters_blobs_tiering.sql"
        )) {
            let _ = ch.query(&stmt).execute().await;
        }

        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let present = [42u8; 32];
        let missing = [43u8; 32];
        #[derive(serde::Serialize, clickhouse::Row)]
        struct Row<'a> {
            tenant_id: &'a str,
            hash: [u8; 32],
            bytes: &'a str,
            size: u32,
        }
        // Declared BEFORE `insert` so it outlives it — `Insert<Row<'a>>`
        // borrows `'a` for its own lifetime, and Rust drops locals in
        // reverse declaration order.
        let tenant_id_str = tenant.to_string();
        let mut insert = ch.insert("blobs").expect("insert init");
        insert
            .write(&Row {
                tenant_id: &tenant_id_str,
                hash: present,
                bytes: "\"the real content\"",
                size: 18,
            })
            .await
            .expect("write blob row");
        insert.end().await.expect("commit blob row");

        let mut a = serde_json::to_string(&ref_json(present)).unwrap();
        let mut b = serde_json::to_string(&ref_json(missing)).unwrap();
        rehydrate(&ch, &tenant, &mut [&mut a, &mut b])
            .await
            .expect("rehydrate must not error on a real ClickHouse");

        let a_val: serde_json::Value = serde_json::from_str(&a).unwrap();
        assert_eq!(a_val, "the real content");
        let b_val: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(b_val["missing"], true);
    }
}
