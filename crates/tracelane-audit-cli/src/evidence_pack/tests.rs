use super::*;

/// The shipped map with one edit applied, re-parsed.
fn edited(edit: impl FnOnce(&mut Value)) -> Result<ControlMap> {
    let mut map: Value = serde_json::from_str(SHIPPED).unwrap();
    edit(&mut map);
    parse_map(&map.to_string())
}
fn refused(edit: impl FnOnce(&mut Value), why: &str) {
    let error = format!("{:#}", edited(edit).unwrap_err());
    assert!(error.contains(why), "{error}");
}
/// Index of the first shipped row with the given status.
fn row(status: &str) -> usize {
    let map: Value = serde_json::from_str(SHIPPED).unwrap();
    let rows = map["controls"].as_array().unwrap();
    rows.iter().position(|c| c["status"] == status).unwrap()
}

#[test]
fn shipped_map_parses() {
    let map = shipped_map().unwrap();
    assert_eq!(map.frameworks.len(), 5);
    assert!(map.controls.len() >= 20);
}
#[test]
fn every_framework_has_a_covered_or_partial_and_a_not_covered_row() {
    let map = shipped_map().unwrap();
    for f in &map.frameworks {
        let of = |s: Status| {
            map.controls
                .iter()
                .any(|c| c.framework == f.id && (c.status == s))
        };
        assert!(of(Status::NotCovered), "{} lists no gap row", f.id);
        assert!(of(Status::Partial), "{} has no anchored row", f.id);
    }
}
#[test]
fn oscal_tokens_are_unique_and_start_with_a_letter() {
    let map = shipped_map().unwrap();
    let tokens: BTreeSet<String> = map.controls.iter().map(token).collect();
    assert_eq!(tokens.len(), map.controls.len());
    assert!(tokens.contains("eu-ai-act-art-12-2-a"), "{tokens:?}");
    assert!(tokens.iter().all(|t| t.starts_with(char::is_alphabetic)));
}
#[test]
fn csv_cell_quotes_commas_and_quotes() {
    assert_eq!(
        csv_row(&["a,b", "say \"x\""]),
        "\"a,b\",\"say \"\"x\"\"\"\r\n"
    );
}
#[test]
fn html_escape_neutralises_markup() {
    assert_eq!(
        esc("<script>&\"</script>"),
        "&lt;script&gt;&amp;&quot;&lt;/script&gt;"
    );
}
#[test]
fn uuid_is_deterministic_and_oscal_shaped() {
    let id = uuid("a");
    assert_eq!(id, uuid("a"));
    assert_ne!(id, uuid("b"));
    assert_eq!(id.as_bytes()[14], b'5');
}

#[test]
fn partial_row_without_anchor_is_refused() {
    let n = row("partial");
    refused(
        |m| {
            m["controls"][n]["anchor"] = Value::Null;
            m["controls"][n]["anchor_text"] = Value::Null;
        },
        "must cite a code anchor",
    );
}
#[test]
fn covered_status_is_refused() {
    // The map can only ever say `partial` or `not covered`.
    let n = row("partial");
    refused(
        |m| m["controls"][n]["status"] = json!("covered"),
        "control map shape",
    );
}
#[test]
fn not_covered_row_with_anchor_is_refused() {
    let n = row("partial");
    refused(
        |m| m["controls"][n]["status"] = json!("not covered"),
        "cites no anchor",
    );
}
#[test]
fn anchor_without_line_number_is_refused() {
    let n = row("partial");
    refused(
        |m| m["controls"][n]["anchor"] = json!("packages/verifier-rust/src/lib.rs"),
        "anchor is not file:line",
    );
}
#[test]
fn row_without_gap_text_is_refused() {
    refused(|m| m["controls"][0]["gap"] = json!(""), "non-empty line");
}
#[test]
fn unknown_status_is_refused() {
    refused(
        |m| m["controls"][0]["status"] = json!("mostly"),
        "control map shape",
    );
}
#[test]
fn unknown_framework_is_refused() {
    refused(
        |m| m["controls"][0]["framework"] = json!("iso-27001"),
        "unknown framework",
    );
}
#[test]
fn duplicate_control_is_refused() {
    refused(
        |m| {
            let first = m["controls"][0].clone();
            m["controls"].as_array_mut().unwrap().push(first);
        },
        "duplicate control row",
    );
}
#[test]
fn unknown_field_is_refused() {
    refused(
        |m| m["controls"][0]["verdict"] = json!("pass"),
        "control map shape",
    );
}
#[test]
fn formula_cell_is_refused() {
    refused(
        |m| m["controls"][0]["requirement"] = json!("=HYPERLINK(\"x\")"),
        "spreadsheet formula",
    );
}
#[test]
fn banned_claim_word_is_refused() {
    for claim in [
        "Fully compliant.",
        "The log is complete.",
        "A tamper-proof log.",
    ] {
        refused(|m| m["limits"][1] = json!(claim), "banned claim word");
    }
}
#[test]
fn framework_without_rows_is_refused() {
    refused(
        |m| {
            let rows = m["controls"].as_array_mut().unwrap();
            rows.retain(|c| c["framework"] != "rbi-free-ai");
        },
        "has no control row",
    );
}

use tracelane_audit_verifier::action::Semantics;

fn report(actions: Semantics) -> Report {
    Report {
        tenant_id: Uuid::from_u128(1),
        head_seq: Some("6".into()),
        head_hash: Some("ab".repeat(32)),
        created_at: "2026-11-20T00:00:00Z".parse().unwrap(),
        rows: 7,
        chain: true,
        head: true,
        actions,
        approvals: Default::default(),
        batch_signatures: 0,
        rekor_included: 0,
        timestamped: false,
        timestamp_reason: None,
        gen_time: None,
        tree_size: None,
        tree_root: None,
        cose_statement: false,
        checkpoint_chain: None,
    }
}
fn busy() -> Semantics {
    Semantics {
        unknown: vec![Uuid::from_u128(1)],
        denied: vec![Uuid::from_u128(2), Uuid::from_u128(3)],
        replayed: 4,
        not_replayable: vec![Uuid::from_u128(4)],
        countersigned: 5,
        uncountersigned: 6,
        refused_workspace_paused: 9,
        ..Semantics::default()
    }
}
/// The `records_in_bundle` cell of one control, from the CSV.
fn csv_records(pack: &Pack, framework: &str, control: &str) -> String {
    let want = format!("\"{framework}\",");
    let line = pack
        .csv
        .split("\r\n")
        .find(|l| l.starts_with(&want) && l.contains(&format!("\"{control}\",")))
        .unwrap();
    line.rsplit(',')
        .next()
        .unwrap()
        .trim_matches('"')
        .to_owned()
}

#[test]
fn counts_follow_the_bundle_per_control() {
    let pack = render(&shipped_map().unwrap(), &report(busy())).unwrap();
    for (framework, control, want) in [
        ("eu-ai-act", "Art. 12(1)", "7"),
        ("eu-ai-act", "Art. 12(2)(a)", "4"),
        ("eu-ai-act", "Art. 12(2)(c)", "3"),
        ("occ-2026-54", "2.3", "2"),
        ("occ-2026-54", "2.10", "9"),
        ("occ-2026-54", "2.14", "7"),
        ("finos-air", "mi-21", "5"),
        ("finos-air", "mi-24", "11"),
        ("rbi-free-ai", "Recommendation 24", "7"),
        ("mas-air-guidelines", "5.3", "9"),
        ("mas-air-guidelines", "5.9", "2"),
    ] {
        assert_eq!(csv_records(&pack, framework, control), want, "{control}");
    }
}
#[test]
fn zero_matches_render_zero_and_uncounted_rows_render_nothing() {
    let pack = render(&shipped_map().unwrap(), &report(Semantics::default())).unwrap();
    assert_eq!(csv_records(&pack, "occ-2026-54", "2.10"), "0");
    assert_eq!(
        csv_records(&pack, "occ-2026-54", "2.15"),
        "",
        "no evidenced_by"
    );
    assert_eq!(csv_records(&pack, "occ-2026-54", "2.2"), "", "not covered");
    assert!(pack.html.contains("0 in this bundle"));
    assert!(pack.html.contains("7 records in this bundle"));
    assert!(pack.html.contains("not counted"));
    let oscal: Value = serde_json::from_str(&pack.oscal).unwrap();
    let props = oscal.to_string();
    assert!(props.contains(
        r#"{"name":"records-in-bundle","ns":"https://tracelane.dev/ns/oscal","value":"0"}"#
    ));
}
#[test]
fn a_count_never_changes_a_status() {
    let map = shipped_map().unwrap();
    let (zero, busy) = (
        render(&map, &report(Semantics::default())).unwrap(),
        render(&map, &report(busy())).unwrap(),
    );
    let statuses = |p: &Pack| -> Vec<String> {
        p.csv
            .split("\r\n")
            .map(|l| l.split(',').nth(3).unwrap_or("").to_owned())
            .collect()
    };
    assert_eq!(statuses(&zero), statuses(&busy));
    assert!(
        map.controls
            .iter()
            .all(|c| c.status != Status::NotCovered || c.evidenced_by.is_none())
    );
}
#[test]
fn counted_keys_are_the_closed_set_and_match_the_report() {
    let counted = counts(&report(busy()));
    let keys: Vec<&str> = counted.iter().map(|(k, ..)| *k).collect();
    assert_eq!(keys, COUNT_KEYS);
    let values: Vec<u64> = counted.iter().map(|(.., n)| *n).collect();
    assert_eq!(values, [7, 1, 2, 4, 1, 5, 6, 9]);
}
#[test]
fn unknown_evidenced_by_key_is_refused() {
    let n = row("partial");
    refused(
        |m| m["controls"][n]["evidenced_by"] = json!(["rows", "tool-calls"]),
        "unknown evidenced_by key tool-calls",
    );
}
#[test]
fn formula_evidenced_by_key_is_refused() {
    let n = row("partial");
    refused(
        |m| m["controls"][n]["evidenced_by"] = json!(["=SUM(A1)"]),
        "spreadsheet formula",
    );
}
#[test]
fn empty_duplicate_or_misplaced_evidenced_by_is_refused() {
    let n = row("partial");
    refused(
        |m| m["controls"][n]["evidenced_by"] = json!([]),
        "at least one key",
    );
    refused(
        |m| m["controls"][n]["evidenced_by"] = json!(["rows", "rows"]),
        "duplicate evidenced_by key",
    );
    let g = row("not covered");
    refused(
        |m| m["controls"][g]["evidenced_by"] = json!(["rows"]),
        "needs a partial row",
    );
}
#[test]
fn mas_rows_parse_with_the_source_and_both_statuses() {
    let map = shipped_map().unwrap();
    let f = map
        .frameworks
        .iter()
        .find(|f| f.id == "mas-air-guidelines")
        .unwrap();
    assert!(f.source.starts_with("https://www.mas.gov.sg/"));
    let rows: Vec<_> = map
        .controls
        .iter()
        .filter(|c| c.framework == f.id)
        .collect();
    assert_eq!(rows.len(), 6);
    assert_eq!(
        rows.iter().filter(|c| c.status == Status::Partial).count(),
        3
    );
}
