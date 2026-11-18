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
    assert_eq!(map.frameworks.len(), 4);
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
