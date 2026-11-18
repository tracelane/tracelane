//! Deterministic ZIP32 STORE profile; PKWARE APPNOTE 6.3.10 §4.3.
//! No extraction, compression, encryption, comments, extra fields or data descriptors.
use anyhow::{Context, Result, ensure};
use std::collections::BTreeMap;
pub type Files = BTreeMap<String, Vec<u8>>;
fn u16le(out: &mut Vec<u8>, n: usize) -> Result<()> {
    out.extend(u16::try_from(n)?.to_le_bytes());
    Ok(())
}
fn u32le(out: &mut Vec<u8>, n: usize) -> Result<()> {
    out.extend(u32::try_from(n)?.to_le_bytes());
    Ok(())
}
/// Errors fail CLOSED on ZIP32 overflow or unsafe names.
pub fn pack(files: &Files) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut directory = Vec::new();
    for (name, bytes) in files {
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b))
                && !name.contains("..")
                && !name.starts_with('/'),
            "invalid member name"
        );
        let offset = out.len();
        let crc = crc32fast::hash(bytes);
        out.extend(0x04034b50u32.to_le_bytes());
        for v in [20, 0, 0, 0, 33] {
            u16le(&mut out, v)?;
        }
        out.extend(crc.to_le_bytes());
        u32le(&mut out, bytes.len())?;
        u32le(&mut out, bytes.len())?;
        u16le(&mut out, name.len())?;
        u16le(&mut out, 0)?;
        out.extend(name.as_bytes());
        out.extend(bytes);
        directory.extend(0x02014b50u32.to_le_bytes());
        u16le(&mut directory, 20)?;
        directory.extend_from_slice(&out[offset + 4..offset + 28]);
        for v in [0, 0, 0, 0] {
            u16le(&mut directory, v)?;
        }
        u32le(&mut directory, 0)?;
        u32le(&mut directory, offset)?;
        directory.extend(name.as_bytes());
    }
    let start = out.len();
    out.extend(&directory);
    out.extend(0x06054b50u32.to_le_bytes());
    u16le(&mut out, 0)?;
    u16le(&mut out, 0)?;
    u16le(&mut out, files.len())?;
    u16le(&mut out, files.len())?;
    u32le(&mut out, directory.len())?;
    u32le(&mut out, start)?;
    u16le(&mut out, 0)?;
    Ok(out)
}
fn word(raw: &[u8], offset: usize, width: usize) -> Result<usize> {
    let mut bytes = [0u8; 8];
    bytes[..width].copy_from_slice(raw.get(offset..offset + width).context("short ZIP")?);
    Ok(usize::try_from(u64::from_le_bytes(bytes))?)
}
/// Errors fail CLOSED. Re-encoding validates every header, CRC, offset and directory byte.
pub fn unpack(raw: &[u8]) -> Result<Files> {
    let mut pos = 0;
    let mut files = Files::new();
    while raw.get(pos..pos + 4) == Some(&0x04034b50u32.to_le_bytes()) {
        ensure!(
            word(raw, pos + 6, 2)? == 0 && word(raw, pos + 8, 2)? == 0,
            "unsupported ZIP profile"
        );
        let size = word(raw, pos + 18, 4)?;
        let name_len = word(raw, pos + 26, 2)?;
        let start = pos + 30;
        let end = start.checked_add(name_len).context("ZIP overflow")?;
        let name = std::str::from_utf8(raw.get(start..end).context("short ZIP name")?)?.to_owned();
        pos = end.checked_add(size).context("ZIP overflow")?;
        ensure!(
            files
                .insert(name, raw.get(end..pos).context("short ZIP data")?.to_vec())
                .is_none(),
            "duplicate ZIP member"
        );
    }
    ensure!(
        !files.is_empty() && pack(&files)? == raw,
        "invalid ZIP structure or CRC"
    );
    Ok(files)
}
// Existing offline CLI resource bound, shared so produced downloads remain compatible.
pub const MAX_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;
/// Export/CLI compatibility check; does not change the archive wire format.
pub fn check_size(bytes: u64) -> Result<()> {
    ensure!(
        bytes <= MAX_BUNDLE_BYTES,
        "action bundle exceeds {MAX_BUNDLE_BYTES} byte limit"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zip_roundtrip() {
        let f = [("test.txt".into(), b"synthetic".to_vec())].into();
        assert_eq!(unpack(&pack(&f).unwrap()).unwrap(), f);
    }
    #[test]
    fn zip_corrupt_refuses() {
        let f = [("test.txt".into(), b"synthetic".to_vec())].into();
        let mut z = pack(&f).unwrap();
        z[40] ^= 1;
        assert_eq!(
            unpack(&z).unwrap_err().to_string(),
            "invalid ZIP structure or CRC"
        );
    }
    #[test]
    fn offline_cli_size_boundary() {
        check_size(MAX_BUNDLE_BYTES).unwrap();
        assert_eq!(
            check_size(MAX_BUNDLE_BYTES + 1).unwrap_err().to_string(),
            "action bundle exceeds 67108864 byte limit"
        );
    }
}
