//! Examiner evidence pack: the reviewed control map joined to one VERIFIED
//! action-bundle report, rendered as CSV, OSCAL JSON and an HTML summary.
//!
//! The pack is a mapping. Nothing here assesses a control, and every output
//! carries the map's `limits` so a reader of any single file sees the gaps.
//! OSCAL model: component-definition, because it is the model for a vendor
//! describing what its own component provides. assessment-results would state
//! an assessor's findings, and no assessment took place.
use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tracelane_audit_verifier::action::bundle::Report;
use uuid::Uuid;

const SHIPPED: &str = include_str!("../evidence/control-map.json");
/// Pinned OSCAL release; the schema fixture in `tests/fixtures` names the same version.
pub const OSCAL_VERSION: &str = "1.1.2";
const NS: &str = "https://tracelane.dev/ns/oscal";
const NOT_COVERED: &str = "not covered";
/// Claim words the map may never carry, checked as whole words.
const BANNED_WORDS: [&str; 6] = [
    "compliant",
    "complete",
    "immutable",
    "certified",
    "conformant",
    "trustless",
];
pub const FILES: [&str; 3] = [
    "controls.csv",
    "oscal-component-definition.json",
    "summary.html",
];

#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
/// There is deliberately no `covered`: the map can only say what a bundle
/// partly evidences or does not evidence.
enum Status {
    #[serde(rename = "partial")]
    Partial,
    #[serde(rename = "not covered")]
    NotCovered,
}
impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Partial => "partial",
            Status::NotCovered => NOT_COVERED,
        }
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Framework {
    id: String,
    title: String,
    source: String,
    identifier_check: String,
    note: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    framework: String,
    control_id: String,
    requirement: String,
    evidence: String,
    anchor: Option<String>,
    anchor_text: Option<String>,
    status: Status,
    gap: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlMap {
    version: String,
    reviewed: String,
    frameworks: Vec<Framework>,
    limits: Vec<String>,
    controls: Vec<Control>,
}
pub struct Pack {
    pub csv: String,
    pub oscal: String,
    pub html: String,
}

fn check_text(value: &Value) -> Result<()> {
    match value {
        Value::String(s) => {
            ensure!(
                !s.is_empty() && s.trim() == s && !s.contains(['\n', '\r']),
                "map text must be one trimmed, non-empty line: {s:?}"
            );
            ensure!(
                !s.starts_with(['=', '+', '-', '@']),
                "map text may not start a spreadsheet formula: {s:?}"
            );
            let lower = s.to_lowercase();
            let banned = lower
                .split(|c: char| !c.is_alphanumeric())
                .any(|w| BANNED_WORDS.contains(&w));
            ensure!(
                !banned && !lower.contains("tamper-proof"),
                "map text carries a banned claim word: {s:?}"
            );
        }
        Value::Array(items) => items.iter().try_for_each(check_text)?,
        Value::Object(fields) => fields.values().try_for_each(check_text)?,
        _ => {}
    }
    Ok(())
}

/// OSCAL `token` for a control: framework id plus the control id, slugged.
fn token(c: &Control) -> String {
    let mut out = String::new();
    for ch in format!("{}-{}", c.framework, c.control_id).chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_end_matches('-').to_owned()
}

/// Parse and validate a control map.
///
/// # Errors
/// Fails CLOSED: a `covered` status, a partial row without a code anchor, a gap-less
/// row, an unknown field/status/framework, a duplicate, a formula cell
/// or a banned claim word refuses the whole map.
pub fn parse_map(raw: &str) -> Result<ControlMap> {
    let value: Value = serde_json::from_str(raw).context("control map is not JSON")?;
    check_text(&value)?;
    let map: ControlMap = serde_json::from_value(value).context("control map shape")?;
    ensure!(!map.limits.is_empty(), "control map lists no limits");
    let mut seen = BTreeSet::new();
    for f in &map.frameworks {
        ensure!(
            f.id.starts_with(|c: char| c.is_ascii_lowercase())
                && f.id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "framework id is not a token: {}",
            f.id
        );
        ensure!(
            map.controls.iter().any(|c| c.framework == f.id),
            "framework {} has no control row",
            f.id
        );
    }
    for c in &map.controls {
        let id = &c.control_id;
        ensure!(
            map.frameworks.iter().any(|f| f.id == c.framework),
            "{id}: unknown framework {}",
            c.framework
        );
        ensure!(seen.insert(token(c)), "{id}: duplicate control row");
        match (c.status, &c.anchor, &c.anchor_text) {
            (Status::NotCovered, None, None) => {
                ensure!(
                    c.evidence == NOT_COVERED,
                    "{id}: evidence must say {NOT_COVERED}"
                );
            }
            (Status::NotCovered, ..) => bail!("{id}: a {NOT_COVERED} row cites no anchor"),
            (_, Some(anchor), Some(_)) => {
                let line = anchor.rsplit_once(':').map(|(_, n)| n.parse::<u32>());
                ensure!(
                    matches!(line, Some(Ok(n)) if n > 0),
                    "{id}: anchor is not file:line"
                );
                ensure!(c.evidence != NOT_COVERED, "{id}: evidence is missing");
            }
            _ => bail!("{id}: a partial row must cite a code anchor"),
        }
    }
    Ok(map)
}

/// The map compiled into this binary.
///
/// # Errors
/// Fails CLOSED if the shipped map does not validate.
pub fn shipped_map() -> Result<ControlMap> {
    parse_map(SHIPPED)
}

/// Deterministic UUID (version-5 layout over SHA-256) so the same bundle and
/// map always produce the same pack bytes.
fn uuid(name: &str) -> String {
    let digest = Sha256::digest(name.as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    Uuid::from_bytes(b).to_string()
}

/// The verifier report numbers the pack restates: (token, label, value).
fn facts(r: &Report) -> Vec<(&'static str, &'static str, String)> {
    let none = || "none".to_owned();
    vec![
        ("tenant-id", "Tenant", r.tenant_id.to_string()),
        ("rows", "Ledger rows verified", r.rows.to_string()),
        (
            "head-seq",
            "Signed head sequence",
            r.head_seq.clone().unwrap_or_else(none),
        ),
        (
            "head-hash",
            "Signed head hash",
            r.head_hash.clone().unwrap_or_else(none),
        ),
        (
            "checkpoint-created-at",
            "Checkpoint time (the signer's statement)",
            r.created_at.to_rfc3339(),
        ),
        (
            "unknown-outcomes",
            "Executions with an unknown outcome",
            r.actions.unknown.len().to_string(),
        ),
        (
            "denied-approvals",
            "Approvals denied",
            r.actions.denied.len().to_string(),
        ),
        (
            "decisions-replayed",
            "Policy decisions replayed",
            r.actions.replayed.to_string(),
        ),
        (
            "decisions-not-replayable",
            "Decisions not replayable (opaque field)",
            r.actions.not_replayable.len().to_string(),
        ),
        (
            "batch-signatures",
            "Batch signatures verified",
            r.batch_signatures.to_string(),
        ),
        (
            "transparency-log-inclusions",
            "Batches with a verified transparency-log inclusion proof",
            r.rekor_included.to_string(),
        ),
        (
            "timestamp-verified",
            "Timestamp verified against a supplied authority certificate",
            match (r.gen_time, r.timestamp_reason) {
                (Some(t), _) => format!("yes, {}", t.to_rfc3339()),
                (None, Some(reason)) => format!("no ({reason})"),
                (None, None) => "no (the bundle carries no timestamp)".to_owned(),
            },
        ),
    ]
}

fn csv_cell(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}
fn csv_row(cells: &[&str]) -> String {
    let cells: Vec<String> = cells.iter().map(|c| csv_cell(c)).collect();
    format!("{}\r\n", cells.join(","))
}
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
fn prop(name: &str, value: &str) -> Value {
    json!({"name": name, "ns": NS, "value": value})
}

/// Render the three pack files from a validated map and a PASSING report.
///
/// # Errors
/// Fails CLOSED if the OSCAL document cannot be serialized.
pub fn render(map: &ControlMap, report: &Report) -> Result<Pack> {
    let facts = facts(report);
    let title = "Tracelane examiner evidence pack (mapping only)";
    let scope = format!(
        "{}/{}/{}",
        report.tenant_id,
        report.head_hash.as_deref().unwrap_or("empty"),
        map.version
    );

    let mut csv = csv_row(&[
        "framework",
        "framework_title",
        "control_id",
        "status",
        "requirement",
        "evidence",
        "code_anchor",
        "gap",
    ]);
    let mut html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{title}</title>\
<style>body{{font:13px/1.45 system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#111}}\
table{{border-collapse:collapse;width:100%;margin:8px 0 24px}}td,th{{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top}}\
h1{{font-size:18px}}h2{{font-size:14px;margin-top:24px}}code{{font-size:12px}}</style></head><body>\
<h1>{title}</h1><p>Control map version {} (reviewed {}). {}</p>\
<h2>Bundle verification (offline, under the key the examiner supplied)</h2><table>",
        esc(&map.version),
        esc(&map.reviewed),
        esc(&map.limits[0]),
    );
    for (_, label, value) in &facts {
        html.push_str(&format!(
            "<tr><th>{}</th><td>{}</td></tr>",
            esc(label),
            esc(value)
        ));
    }
    html.push_str("</table><h2>What this pack does not show</h2><ul>");
    for limit in &map.limits {
        html.push_str(&format!("<li>{}</li>", esc(limit)));
    }
    html.push_str("</ul>");

    let mut implementations = Vec::new();
    for f in &map.frameworks {
        html.push_str(&format!(
            "<h2>{}</h2><p>Source: {}. {} {}</p><table><tr><th>Control</th><th>Status</th>\
<th>Requirement (paraphrase)</th><th>Evidence in the bundle</th><th>Code anchor</th><th>Gap</th></tr>",
            esc(&f.title),
            esc(&f.source),
            esc(&f.identifier_check),
            esc(&f.note)
        ));
        let mut requirements = Vec::new();
        for c in map.controls.iter().filter(|c| c.framework == f.id) {
            let (status, anchor) = (c.status.label(), c.anchor.as_deref().unwrap_or(""));
            csv.push_str(&csv_row(&[
                &f.id,
                &f.title,
                &c.control_id,
                status,
                &c.requirement,
                &c.evidence,
                anchor,
                &c.gap,
            ]));
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
                esc(&c.control_id),
                status,
                esc(&c.requirement),
                esc(&c.evidence),
                esc(anchor),
                esc(&c.gap)
            ));
            let mut props = vec![
                prop("mapping-status", status),
                prop("control-label", &c.control_id),
                prop("evidence", &c.evidence),
            ];
            if let Some(anchor) = &c.anchor {
                props.push(prop("code-anchor", anchor));
            }
            requirements.push(json!({
                "uuid": uuid(&format!("{scope}/{}", token(c))),
                "control-id": token(c),
                "description": format!("Mapping status: {status}. {}", c.requirement),
                "props": props,
                "remarks": c.gap,
            }));
        }
        html.push_str("</table>");
        implementations.push(json!({
            "uuid": uuid(&format!("{scope}/{}", f.id)),
            "source": f.source,
            "description": format!("{}. {} {}", f.title, f.identifier_check, f.note),
            "implemented-requirements": requirements,
        }));
    }
    for (n, limit) in map.limits.iter().enumerate() {
        csv.push_str(&csv_row(&[
            "pack",
            "Limits of this pack",
            &format!("limit-{}", n + 1),
            NOT_COVERED,
            "Pack-level limit",
            NOT_COVERED,
            "",
            limit,
        ]));
    }
    html.push_str("</body></html>\n");

    let oscal = json!({"component-definition": {
        "uuid": uuid(&scope),
        "metadata": {
            "title": title,
            "last-modified": report.created_at.to_rfc3339(),
            "version": map.version,
            "oscal-version": OSCAL_VERSION,
            "remarks": map.limits.join("\n\n"),
        },
        "components": [{
            "uuid": uuid(&format!("{scope}/component")),
            "type": "software",
            "title": "Tracelane action ledger, as exported in one verified bundle",
            "description": "Evidence one offline-verified action bundle carries for each mapped control. last-modified is the bundle checkpoint time.",
            "props": facts.iter().map(|(name, _, value)| prop(name, value)).collect::<Vec<_>>(),
            "control-implementations": implementations,
        }],
    }});
    Ok(Pack {
        csv,
        oscal: format!("{}\n", serde_json::to_string_pretty(&oscal)?),
        html,
    })
}

/// Write the pack into `out`, which must be absent or an empty directory.
///
/// # Errors
/// Fails CLOSED: refuses a non-empty directory (a stale file beside a new pack
/// would read as one pack). Each file is opened `create_new`, so a path planted
/// after that check (a symlink included) is refused, never followed or
/// truncated. On any failure it removes only what this call created.
pub fn write(out: &Path, pack: &Pack) -> Result<()> {
    let created_dir = !out.exists();
    if !created_dir {
        ensure!(
            out.read_dir().is_ok_and(|mut d| d.next().is_none()),
            "--out must be a new or empty directory: {}",
            out.display()
        );
    }
    std::fs::create_dir_all(out).with_context(|| format!("create {}", out.display()))?;
    let bodies = [&pack.csv, &pack.oscal, &pack.html];
    let mut written = Vec::new();
    for (name, body) in FILES.iter().zip(bodies) {
        let result = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(out.join(name))
            .and_then(|mut file| file.write_all(body.as_bytes()));
        if let Err(e) = result {
            for done in written {
                let _ = std::fs::remove_file(out.join(done));
            }
            if created_dir {
                let _ = std::fs::remove_dir(out);
            }
            return Err(e).with_context(|| format!("write {name}"));
        }
        written.push(name);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
