//! End-to-end: the `evidence-pack` subcommand against synthetic action bundles.
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracelane_audit_verifier::action::{archive::Files, bundle::seal, canonical_json};

const TENANT: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const MAP: &str = include_str!("../evidence/control-map.json");
const SCHEMA: &str = include_str!("fixtures/oscal_component_schema-1.1.2.json");

fn lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend((bytes.len() as u64).to_be_bytes());
    buf.extend(bytes);
}
/// Synthetic three-row v2.1 ledger with a signed covering head. Not prod data.
fn bundle_files() -> (Files, [u8; 32]) {
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let pin: [u8; 32] = key.public_key().as_ref().try_into().unwrap();
    let tenant = uuid::Uuid::from_bytes(TENANT);
    let mut prev: [u8; 32] =
        Sha256::digest([b"tracelane-audit-v2-genesis\0", &TENANT[..]].concat()).into();
    let mut ledger = String::new();
    for seq in 0u64..3 {
        let mut buf = b"tracelane-audit-row-v2\0".to_vec();
        lp(&mut buf, &TENANT);
        buf.extend(seq.to_be_bytes());
        for part in [&b"fixture"[..], b"test", b"{}", &prev] {
            lp(&mut buf, part);
        }
        let hash: [u8; 32] = Sha256::digest(&buf).into();
        let row = json!({"format":"v2.1","tenant_id":tenant,"seq":seq,"event_time":"2026-10-30T12:00:00Z","event_type":"fixture","actor":"test","payload":"{}","prev_hash":hex::encode(prev),"row_hash":hex::encode(hash)});
        ledger.push_str(&format!("{row}\n"));
        prev = hash;
    }
    let head = canonical_json(&json!({"domain":"tracelane.action-head.v1","schema_version":1,"tenant_id":tenant,"seq":"2","head_hash":hex::encode(prev),"created_at":"2026-10-30T12:00:00Z","key_id":hex::encode(Sha256::digest(pin)),"previous_checkpoint_digest":null}).to_string()).unwrap();
    let sig = key.sign(head.as_bytes()).as_ref().to_vec();
    let files = [
        ("ledger.ndjson".to_owned(), ledger.into_bytes()),
        ("checkpoint.json".to_owned(), head.into_bytes()),
        ("checkpoint.sig".to_owned(), sig),
    ];
    (files.into(), pin)
}
struct Run {
    out: PathBuf,
    output: Output,
    _dir: tempfile::TempDir,
}
impl Run {
    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.out.join(name)).unwrap()
    }
    fn oscal(&self) -> Value {
        serde_json::from_str(&self.read("oscal-component-definition.json")).unwrap()
    }
    fn refused(&self, code: i32, why: &str) {
        let stderr = String::from_utf8_lossy(&self.output.stderr);
        assert_eq!(self.output.status.code(), Some(code), "{stderr}");
        assert!(stderr.contains(why), "{stderr}");
        assert!(!self.out.exists(), "a refused run must write no pack");
    }
}
fn run_with(files: Files, pin: Option<[u8; 32]>, prepare: impl FnOnce(&Path)) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let (zip, out) = (dir.path().join("bundle.zip"), dir.path().join("pack"));
    std::fs::write(&zip, seal(files).unwrap()).unwrap();
    prepare(&out);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tracelane-audit"));
    cmd.arg("evidence-pack").arg("--file").arg(&zip);
    cmd.arg("--out").arg(&out);
    if let Some(pin) = pin {
        let key = dir.path().join("tenant.pub");
        std::fs::write(&key, hex::encode(pin)).unwrap();
        cmd.arg("--pubkey").arg(key);
    }
    let output = cmd.output().unwrap();
    Run {
        out,
        output,
        _dir: dir,
    }
}
fn good() -> Run {
    let (files, pin) = bundle_files();
    let run = run_with(files, Some(pin), |_| {});
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert_eq!(run.output.status.code(), Some(0), "{stderr}");
    run
}
fn map() -> Value {
    serde_json::from_str(MAP).unwrap()
}
fn schema_errors(instance: &Value) -> Option<String> {
    let mut schemas = boon::Schemas::new();
    let mut compiler = boon::Compiler::new();
    let mut schema: Value = serde_json::from_str(SCHEMA).unwrap();
    assert!(schema["$id"].as_str().unwrap().contains("/oscal/1.1.2/"));
    // The NIST file is vendored byte-for-byte. Some of its definitions put `$id`
    // beside `$ref`; draft-07 ignores siblings of `$ref`, so a strict validator
    // cannot resolve those anchors. Wrap each such `$ref` in `allOf` in memory,
    // which keeps the `$id` live and constrains exactly the same.
    fn keep_anchors(node: &mut Value) {
        match node {
            Value::Object(map) => {
                if map.contains_key("$id") && map.contains_key("$ref") {
                    let target = map.remove("$ref").unwrap();
                    map.insert("allOf".into(), json!([{ "$ref": target }]));
                }
                map.values_mut().for_each(keep_anchors);
            }
            Value::Array(items) => items.iter_mut().for_each(keep_anchors),
            _ => {}
        }
    }
    keep_anchors(&mut schema["definitions"]);
    compiler.add_resource("oscal.json", schema).unwrap();
    let index = compiler.compile("oscal.json", &mut schemas).unwrap();
    schemas
        .validate(instance, index)
        .err()
        .map(|e| e.to_string())
}

#[test]
fn pack_writes_exactly_three_files() {
    let run = good();
    let mut names: Vec<_> = std::fs::read_dir(&run.out)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "controls.csv",
            "oscal-component-definition.json",
            "summary.html"
        ]
    );
}
#[test]
fn oscal_validates_against_pinned_schema() {
    let oscal = good().oscal();
    assert_eq!(schema_errors(&oscal), None);
    let definition = &oscal["component-definition"];
    assert_eq!(definition["metadata"]["oscal-version"], "1.1.2");
    let rows: usize = definition["components"][0]["control-implementations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["implemented-requirements"].as_array().unwrap().len())
        .sum();
    assert_eq!(rows, map()["controls"].as_array().unwrap().len());
}
#[test]
fn schema_rejects_a_broken_oscal_document() {
    // Proves the validator blocks: a missing required field and a bad token both fail.
    let mut missing = good().oscal();
    let metadata = missing["component-definition"]["metadata"].as_object_mut();
    metadata.unwrap().remove("oscal-version");
    assert!(schema_errors(&missing).is_some());
    let mut bad_token = good().oscal();
    bad_token["component-definition"]["components"][0]["control-implementations"][0]["implemented-requirements"]
        [0]["control-id"] = json!("Art. 12(1)");
    assert!(schema_errors(&bad_token).is_some());
}
#[test]
fn csv_has_one_row_per_control_and_per_limit() {
    let csv = good().read("controls.csv");
    let (controls, limits) = (map()["controls"].clone(), map()["limits"].clone());
    let (controls, limits) = (
        controls.as_array().unwrap().len(),
        limits.as_array().unwrap().len(),
    );
    assert_eq!(csv.matches("\r\n").count(), 1 + controls + limits);
    assert!(csv.starts_with("\"framework\",\"framework_title\",\"control_id\",\"status\""));
    assert!(csv.contains("\"Art. 12(2)(a)\",\"partial\""), "{csv}");
    assert!(csv.contains("\"pack\",\"Limits of this pack\",\"limit-2\",\"not covered\""));
}
#[test]
fn html_lists_the_verifier_report_numbers() {
    let run = good();
    let html = run.read("summary.html");
    let head = bundle_files().0["checkpoint.json"].clone();
    let head: Value = serde_json::from_slice(&head).unwrap();
    assert!(
        html.contains("<th>Ledger rows verified</th><td>3</td>"),
        "{html}"
    );
    assert!(html.contains("<th>Signed head sequence</th><td>2</td>"));
    assert!(html.contains(head["head_hash"].as_str().unwrap()));
    assert!(html.contains("00000000-0000-0000-0000-000000000001"));
    assert!(html.contains("no (the bundle carries no timestamp)"));
    let props = run.oscal()["component-definition"]["components"][0]["props"].clone();
    assert!(
        props
            .as_array()
            .unwrap()
            .contains(&json!({"name":"rows","ns":"https://tracelane.dev/ns/oscal","value":"3"}))
    );
}
#[test]
fn every_output_lists_every_gap() {
    let run = good();
    let escape = |s: &str| s.replace('&', "&amp;").replace('"', "&quot;");
    let (csv, html) = (run.read("controls.csv"), run.read("summary.html"));
    let oscal = run.oscal().to_string();
    let json_text = |s: &str| serde_json::to_string(s).unwrap();
    let map = map();
    let gaps = map["controls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| &c["gap"]);
    for text in map["limits"].as_array().unwrap().iter().chain(gaps) {
        let text = text.as_str().unwrap();
        assert!(csv.contains(&text.replace('"', "\"\"")), "csv: {text}");
        assert!(html.contains(&escape(text)), "html: {text}");
        let inner = json_text(text);
        assert!(oscal.contains(&inner[1..inner.len() - 1]), "oscal: {text}");
    }
    assert!(html.contains("No per-record inclusion proof"));
    assert!(html.contains("No signed scope attestation"));
}
#[test]
fn pack_never_claims() {
    let run = good();
    for name in [
        "controls.csv",
        "oscal-component-definition.json",
        "summary.html",
    ] {
        let text = run.read(name).to_lowercase();
        let words: Vec<&str> = text.split(|c: char| !c.is_alphanumeric()).collect();
        for banned in [
            "compliant",
            "complete",
            "immutable",
            "certified",
            "conformant",
        ] {
            assert!(!words.contains(&banned), "{name} says {banned}");
        }
        assert!(!text.contains("tamper-proof"), "{name}");
        assert!(text.contains("not an assessment"), "{name}");
    }
}
#[test]
fn output_is_deterministic() {
    let (a, b) = (good(), good());
    for name in [
        "controls.csv",
        "oscal-component-definition.json",
        "summary.html",
    ] {
        assert_eq!(a.read(name), b.read(name), "{name}");
    }
}
#[test]
fn anchors_resolve_to_the_named_source_line() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut checked = 0;
    for control in map()["controls"].as_array().unwrap() {
        let Some(anchor) = control["anchor"].as_str() else {
            assert_eq!(control["status"], "not covered");
            continue;
        };
        let (file, line) = anchor.rsplit_once(':').unwrap();
        let source = std::fs::read_to_string(root.join(file)).unwrap();
        let text = source.lines().nth(line.parse::<usize>().unwrap() - 1);
        let want = control["anchor_text"].as_str().unwrap();
        assert!(text.is_some_and(|t| t.contains(want)), "{anchor}: {text:?}");
        checked += 1;
    }
    assert!(checked >= 8, "only {checked} anchors checked");
}
#[test]
fn csv_rows_match_the_map_statuses() {
    let csv = good().read("controls.csv");
    for control in map()["controls"].as_array().unwrap() {
        let cell = |k: &str| format!("\"{}\"", control[k].as_str().unwrap());
        let want = format!("{},{},", cell("control_id"), cell("status"));
        assert!(csv.contains(&want), "{want}");
    }
}

#[test]
fn tampered_bundle_produces_no_pack() {
    let (mut files, pin) = bundle_files();
    let ledger = String::from_utf8(files["ledger.ndjson"].clone()).unwrap();
    let mut rows: Vec<&str> = ledger.lines().collect();
    rows.remove(1);
    files.insert(
        "ledger.ndjson".into(),
        format!("{}\n", rows.join("\n")).into_bytes(),
    );
    run_with(files, Some(pin), |_| {}).refused(4, "previous hash mismatch at 1");
}
#[test]
fn wrong_key_produces_no_pack() {
    let (files, _) = bundle_files();
    run_with(files, Some([9; 32]), |_| {}).refused(5, "does not verify under external pin");
}
#[test]
fn missing_pubkey_produces_no_pack() {
    let (files, _) = bundle_files();
    run_with(files, None, |_| {}).refused(5, "external --pubkey file required");
}
#[test]
fn stripped_checkpoint_signature_produces_no_pack() {
    let (mut files, pin) = bundle_files();
    files.remove("checkpoint.sig");
    run_with(files, Some(pin), |_| {}).refused(4, "missing checkpoint.sig");
}
#[cfg(unix)]
#[test]
fn symlink_in_out_dir_is_refused_and_its_target_untouched() {
    let (files, pin) = bundle_files();
    let run = run_with(files, Some(pin), |out| {
        std::fs::create_dir(out).unwrap();
        let target = out.parent().unwrap().join("victim");
        std::fs::write(&target, "keep").unwrap();
        std::os::unix::fs::symlink(&target, out.join("controls.csv")).unwrap();
    });
    assert_eq!(run.output.status.code(), Some(2));
    let victim = run.out.parent().unwrap().join("victim");
    assert_eq!(std::fs::read_to_string(victim).unwrap(), "keep");
    assert!(!run.out.join("summary.html").exists());
}
#[test]
fn non_empty_out_dir_is_refused_and_left_untouched() {
    let (files, pin) = bundle_files();
    let run = run_with(files, Some(pin), |out| {
        std::fs::create_dir(out).unwrap();
        std::fs::write(out.join("summary.html"), "stale").unwrap();
    });
    assert_eq!(run.output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert!(stderr.contains("new or empty directory"), "{stderr}");
    assert_eq!(run.read("summary.html"), "stale");
    assert!(!run.out.join("controls.csv").exists());
}
