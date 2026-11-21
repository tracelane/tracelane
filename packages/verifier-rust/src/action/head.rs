//! Shared strict grammar for covering heads and historical checkpoint statements.
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Head {
    domain: String,
    pub schema_version: u32,
    pub tenant_id: Uuid,
    pub seq: Option<String>,
    pub head_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub key_id: String,
    pub previous_checkpoint_digest: Option<String>,
    tree_size: Option<String>,
    tree_root: Option<String>,
    #[serde(skip)]
    pub tree: Option<(u64, super::tree::Hash)>,
}

fn hash(text: &str) -> Result<super::tree::Hash> {
    ensure!(
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid signed tree hash"
    );
    hex::decode(text)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid signed tree hash"))
}

/// Decode either exact wire grammar. Errors fail CLOSED; legacy grammar is not widened.
pub(super) fn parse(text: &str) -> Result<Head> {
    let fields: serde_json::Value = serde_json::from_str(text)?;
    let mut head: Head = serde_json::from_value(fields.clone())?;
    ensure!(
        head.domain == "tracelane.action-head.v1" && matches!(head.schema_version, 1 | 2),
        "checkpoint domain/version"
    );
    if head.schema_version == 1 {
        ensure!(
            fields.get("tree_size").is_none() && fields.get("tree_root").is_none(),
            "legacy checkpoint has tree fields"
        );
        return Ok(head);
    }
    let size_text = head
        .tree_size
        .as_deref()
        .context("signed tree size required")?;
    let size: u64 = size_text.parse().context("invalid signed tree size")?;
    ensure!(
        size.to_string() == size_text,
        "noncanonical signed tree size"
    );
    let root = hash(
        head.tree_root
            .as_deref()
            .context("signed tree root required")?,
    )?;
    if size == 0 {
        ensure!(
            head.seq.is_none() && head.head_hash.is_none() && root == crate::sha256(b""),
            "invalid signed empty tree"
        );
    } else {
        ensure!(
            head.seq.as_deref() == Some((size - 1).to_string().as_str()),
            "signed tree size does not match checkpoint sequence"
        );
        hash(
            head.head_hash
                .as_deref()
                .context("signed tree head hash required")?,
        )?;
    }
    head.tree = Some((size, root));
    Ok(head)
}
