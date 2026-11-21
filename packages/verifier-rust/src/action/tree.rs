//! RFC 6962 Merkle tree over action-ledger row hashes, with a C2SP signed-note
//! checkpoint (c2sp.org/tlog-checkpoint, c2sp.org/signed-note). Fully offline.
//! Tamper-evident only: a proof shows a row is consistent with a signed tree
//! head. It does not show that every action was recorded. No witness
//! cosignature is required or checked; unknown signature lines are ignored.
use anyhow::{Context, Result, bail, ensure};
use uuid::Uuid;

pub type Hash = [u8; 32];
/// Bundle member carrying the signed checkpoint.
pub const MEMBER: &str = "tree-checkpoint.note";
/// Local parse bound for untrusted notes; a wire-format limit, not a plan limit.
pub const MAX_SIGNATURES: usize = 16;
const SIGNATURE_PREFIX: &str = "\u{2014} ";
const ED25519: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: Hash,
}

/// RFC 6962 §2.1 leaf hash: SHA-256(0x00 ‖ data).
pub fn leaf_hash(data: &[u8]) -> Hash {
    crate::sha256(&[&[crate::MERKLE_LEAF_PREFIX][..], data].concat())
}
fn node(left: &Hash, right: &Hash) -> Hash {
    crate::sha256(&[&[crate::MERKLE_NODE_PREFIX][..], left, right].concat())
}
/// Largest power of two strictly below `n` (n >= 2).
fn split(n: usize) -> usize {
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}
/// RFC 6962 §2.1 Merkle tree hash over LEAF HASHES. The empty tree is SHA-256("").
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => crate::sha256(b""),
        1 => leaves[0],
        n => {
            let (left, right) = leaves.split_at(split(n));
            node(&root(left), &root(right))
        }
    }
}
/// Incrementally derives monotonically requested roots; each supplied leaf is consumed once.
/// Only O(log N) subtree hashes are retained in addition to the caller's leaf buffer.
#[derive(Default)]
pub(super) struct PrefixRoots {
    count: usize,
    nodes: Vec<Option<Hash>>,
}
impl PrefixRoots {
    /// Errors fail CLOSED for a regressing prefix or one outside the verified ledger.
    pub(super) fn at(&mut self, leaves: &[Hash], size: u64) -> Result<Hash> {
        let end = usize::try_from(size)?;
        ensure!(
            end >= self.count && end <= leaves.len(),
            "signed tree prefix outside verified ledger"
        );
        for leaf in &leaves[self.count..end] {
            let mut carry = *leaf;
            let mut level = 0;
            loop {
                if level == self.nodes.len() {
                    self.nodes.push(None);
                }
                if let Some(left) = self.nodes[level].take() {
                    carry = node(&left, &carry);
                    level += 1;
                } else {
                    self.nodes[level] = Some(carry);
                    break;
                }
            }
        }
        self.count = end;
        let mut root = None;
        for left in self.nodes.iter().flatten() {
            root = Some(root.map_or(*left, |right| node(left, &right)));
        }
        Ok(root.unwrap_or_else(|| crate::sha256(b"")))
    }
}
/// RFC 6962 §2.1.1 audit path for `leaves[index]`.
///
/// # Errors
/// Fails when `index` is outside the tree.
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Result<Vec<Hash>> {
    ensure!(index < leaves.len(), "leaf index outside the tree");
    if leaves.len() == 1 {
        return Ok(Vec::new());
    }
    let (left, right) = leaves.split_at(split(leaves.len()));
    let (mut path, sibling) = if index < left.len() {
        (inclusion_proof(left, index)?, root(right))
    } else {
        (inclusion_proof(right, index - left.len())?, root(left))
    };
    path.push(sibling);
    Ok(path)
}
/// RFC 6962 §2.1.2 consistency proof between the first `old` leaves and all of `leaves`.
///
/// # Errors
/// Fails when `old` exceeds the tree size.
pub fn consistency_proof(leaves: &[Hash], old: usize) -> Result<Vec<Hash>> {
    ensure!(old <= leaves.len(), "old tree is larger than the new tree");
    fn sub(old: usize, leaves: &[Hash], whole: bool) -> Vec<Hash> {
        if old == leaves.len() {
            return if whole {
                Vec::new()
            } else {
                vec![root(leaves)]
            };
        }
        let (left, right) = leaves.split_at(split(leaves.len()));
        let (mut path, sibling) = if old <= left.len() {
            (sub(old, left, whole), root(right))
        } else {
            (sub(old - left.len(), right, false), root(left))
        };
        path.push(sibling);
        path
    }
    Ok(if old == 0 {
        Vec::new()
    } else {
        sub(old, leaves, true)
    })
}
/// Verify an audit path (procedure of RFC 9162 §2.1.3.2; same proofs as RFC 6962).
///
/// # Errors
/// Fails CLOSED on any mismatch, wrong length or out-of-range index.
pub fn verify_inclusion(
    leaf: &Hash,
    index: u64,
    size: u64,
    proof: &[Hash],
    expected: &Hash,
) -> Result<()> {
    ensure!(index < size, "leaf index outside the tree");
    let (mut f, mut s, mut r) = (index, size - 1, *leaf);
    for p in proof {
        ensure!(s != 0, "inclusion proof too long");
        if f & 1 == 1 || f == s {
            r = node(p, &r);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            r = node(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    ensure!(
        s == 0 && r == *expected,
        "inclusion proof does not match the signed root"
    );
    Ok(())
}
/// Verify a consistency proof (procedure of RFC 9162 §2.1.4.2).
///
/// # Errors
/// Fails CLOSED on any mismatch, wrong proof shape or a shrinking tree.
pub fn verify_consistency(
    old: u64,
    new: u64,
    old_root: &Hash,
    new_root: &Hash,
    proof: &[Hash],
) -> Result<()> {
    ensure!(old <= new, "old tree is larger than the new tree");
    if old == new || old == 0 {
        // An empty old tree has one root, SHA-256 of nothing; RFC 9162 leaves size 0 undefined.
        let expected_old = if old == 0 { root(&[]) } else { *new_root };
        ensure!(
            proof.is_empty() && *old_root == expected_old,
            "consistency proof does not match the signed roots"
        );
        return Ok(());
    }
    // An old tree that is a full subtree is its own first proof element.
    let (seed, rest) = if old.is_power_of_two() {
        (old_root, proof)
    } else {
        proof.split_first().context("consistency proof is empty")?
    };
    let (mut f, mut s) = (old - 1, new - 1);
    while f & 1 == 1 {
        f >>= 1;
        s >>= 1;
    }
    let (mut fr, mut sr) = (*seed, *seed);
    for c in rest {
        ensure!(s != 0, "consistency proof too long");
        if f & 1 == 1 || f == s {
            fr = node(c, &fr);
            sr = node(c, &sr);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            sr = node(&sr, c);
        }
        f >>= 1;
        s >>= 1;
    }
    ensure!(
        s == 0 && fr == *old_root && sr == *new_root,
        "consistency proof does not match the signed roots"
    );
    Ok(())
}

/// Checkpoint origin and signed-note key name for one tenant's action ledger.
pub fn origin(tenant: Uuid) -> String {
    format!("tracelane.dev/action-ledger/{tenant}")
}
/// C2SP signed-note key id: SHA-256(name ‖ 0x0A ‖ 0x01 ‖ Ed25519 public key)[:4].
pub fn key_id(name: &str, pubkey: &[u8; 32]) -> [u8; 4] {
    let hash = crate::sha256(&[name.as_bytes(), &[b'\n', ED25519], pubkey].concat());
    [hash[0], hash[1], hash[2], hash[3]]
}
/// C2SP tlog-checkpoint body, the exact bytes the note signature covers.
pub fn checkpoint_body(origin: &str, size: u64, root: &Hash) -> String {
    format!("{origin}\n{size}\n{}\n", base64(root))
}
/// Assemble a signed note from `body` and an Ed25519 `signature` over `body`.
pub fn signed_note(body: &str, name: &str, pubkey: &[u8; 32], signature: &[u8]) -> String {
    let blob = [&key_id(name, pubkey)[..], signature].concat();
    format!("{body}\n{SIGNATURE_PREFIX}{name} {}\n", base64(&blob))
}
/// Return the note text once a signature by (`name`, `pin`) verifies over it.
/// Signature lines from other keys are ignored, as C2SP signed-note requires.
///
/// # Errors
/// Fails CLOSED on malformed input, no signature from the pinned key, or a bad one.
pub fn verify_note<'a>(note: &'a [u8], name: &str, pin: &[u8; 32]) -> Result<&'a str> {
    let note = std::str::from_utf8(note).context("note is not UTF-8")?;
    ensure!(
        !note.chars().any(|c| c != '\n' && c.is_control()),
        "note contains control characters"
    );
    let cut = note.rfind("\n\n").context("note has no signature block")?;
    let (text, signatures) = (&note[..=cut], &note[cut + 2..]);
    let signatures = signatures
        .strip_suffix('\n')
        .context("note does not end with a newline")?;
    ensure!(
        signatures.split('\n').count() <= MAX_SIGNATURES,
        "too many note signatures"
    );
    let id = key_id(name, pin);
    let mut verified = false;
    for line in signatures.split('\n') {
        let (signer, blob) = line
            .strip_prefix(SIGNATURE_PREFIX)
            .and_then(|l| l.split_once(' '))
            .context("malformed note signature line")?;
        let text_blob = blob;
        let blob = crate::base64_decode(blob).map_err(anyhow::Error::msg)?;
        // One spelling per signature (Go's strict StdEncoding): a re-spelled blob is refused.
        ensure!(base64(&blob) == text_blob, "malformed note signature line");
        ensure!(
            !signer.is_empty() && blob.len() > 4,
            "malformed note signature line"
        );
        if signer == name && blob[..4] == id {
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pin)
                .verify(text.as_bytes(), &blob[4..])
                .map_err(|_| anyhow::anyhow!("note signature does not verify under the pin"))?;
            verified = true;
        }
    }
    ensure!(verified, "note carries no signature from the pinned key");
    Ok(text)
}
/// Verify a checkpoint note under the pinned key and parse it. The key name is the origin.
///
/// # Errors
/// Fails CLOSED: bad signature, another origin, extension lines or a non-canonical body.
pub fn open_checkpoint(note: &[u8], origin: &str, pin: &[u8; 32]) -> Result<Checkpoint> {
    let body = verify_note(note, origin, pin)?;
    let lines: Vec<&str> = body.split('\n').collect();
    let [log, size, root, ""] = lines[..] else {
        bail!("checkpoint body is not origin, size and root");
    };
    ensure!(log == origin, "checkpoint is for another origin");
    let checkpoint = Checkpoint {
        origin: log.to_owned(),
        size: size.parse().context("checkpoint tree size")?,
        root: crate::base64_decode(root)
            .map_err(anyhow::Error::msg)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("checkpoint root is not 32 bytes"))?,
    };
    // Re-encoding refuses leading zeros, signs and non-canonical base64 in one check.
    ensure!(
        checkpoint_body(origin, checkpoint.size, &checkpoint.root) == body,
        "checkpoint body is not canonical"
    );
    Ok(checkpoint)
}
/// Leaf hashes for every ledger row in an action-bundle `ledger.ndjson`, in file
/// order. Anchor records are not leaves. Does NOT check the hash chain.
///
/// # Errors
/// Fails on a line that is not JSON or a row without a 32-byte hex `row_hash`.
pub fn ledger_leaves(ndjson: &[u8]) -> Result<Vec<Hash>> {
    let mut leaves = Vec::new();
    for line in std::str::from_utf8(ndjson)?.lines() {
        let value: serde_json::Value = serde_json::from_str(line)?;
        if value.get("type").and_then(|v| v.as_str()) == Some("anchor") {
            continue;
        }
        let hash = value["row_hash"].as_str().context("row without row_hash")?;
        let raw: Hash = hex::decode(hash)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("row_hash is not 32 bytes"))?;
        leaves.push(leaf_hash(&raw));
    }
    Ok(leaves)
}
/// Check a bundle's optional checkpoint member against the rows the verifier has
/// already chained (`leaves`). `None` when the bundle carries no checkpoint: older
/// bundles have none, and the unsigned manifest cannot tell absence from stripping,
/// so a caller that needs the tree must check for `Some`.
///
/// # Errors
/// Fails CLOSED with the bundle exit code: 5 when the note does not verify under
/// the pin for this tenant, 4 when it is signed but disagrees with the rows.
pub fn check_member(
    files: &super::archive::Files,
    tenant: Uuid,
    pin: &[u8; 32],
    leaves: &[Hash],
) -> Result<Option<Hash>, (u8, String)> {
    let Some(note) = files.get(MEMBER) else {
        return Ok(None);
    };
    let signed = open_checkpoint(note, &origin(tenant), pin)
        .map_err(|e| (5, format!("tree checkpoint: {e}")))?;
    let recomputed = root(leaves);
    if signed.size != leaves.len() as u64 || signed.root != recomputed {
        return Err((4, "tree checkpoint does not match the ledger rows".into()));
    }
    Ok(Some(recomputed))
}
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, b| (n << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
        for index in 0..4 {
            out.push(if index > chunk.len() {
                '='
            } else {
                ALPHABET[((n >> (18 - 6 * index)) & 63) as usize] as char
            });
        }
    }
    out
}
#[cfg(test)]
mod tests;
