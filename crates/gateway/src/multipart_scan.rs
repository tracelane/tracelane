//! `OG-06` §3.1 — a bounded, STREAMING `multipart/form-data` scanner.
//!
//! The media and files routes must read `model` (and `purpose`, and a prompt) out of a
//! multipart body and then forward the caller's bytes UNCHANGED: a re-encoded body is a
//! different request. So this scanner never owns the body. The caller feeds it each
//! chunk as it passes and keeps (or forwards) the bytes itself; the scanner reports
//! what it saw — text fields, and where each file part's data begins and ends, as
//! ABSOLUTE stream offsets — and holds only a bounded window itself (a part's header
//! block, one text value, or a boundary-sized tail of file data).
//!
//! ## Strict on purpose: a parser differential is a bypass
//!
//! The gateway decides on what THIS parser reads (`model` → provider + billing,
//! `purpose=batch` → buffer and validate every JSONL line). The provider decides on what
//! ITS parser reads. Anywhere the two could disagree is a way to make the gateway
//! govern one request while the provider serves another — a duplicate `purpose` part, a
//! preamble before the first boundary, an RFC 2231 `filename*` the other side reads as a
//! file, a `Content-Transfer-Encoding: base64` part. Every such shape is refused here
//! rather than interpreted: `Malformed`. The caller additionally refuses a DUPLICATE of
//! any field it routes on.
//!
//! **Fail-CLOSED:** any `Err` means the body is not forwarded (or, mid-stream, is
//! aborted).

/// Header block per part. A part with more headers than this is not a form field.
const MAX_HEADER_BYTES: usize = 8 * 1024;
/// RFC 2046 §5.1.1: a boundary is 1–70 characters.
const MAX_BOUNDARY_LEN: usize = 70;

/// Why a multipart body was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScanError {
    /// The shape is not one this gateway will interpret (the reason is a fixed string —
    /// never a fragment of the body).
    Malformed(&'static str),
    /// A text field longer than the table's cap.
    FieldTooLarge,
    /// More parts than the table allows.
    TooManyParts,
}

impl ScanError {
    pub(crate) fn message(&self) -> &'static str {
        match self {
            Self::Malformed(m) => m,
            Self::FieldTooLarge => "a multipart text field exceeds the size cap",
            Self::TooManyParts => "the multipart body has too many parts",
        }
    }
}

/// What the scanner saw, in stream order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    /// A complete text part.
    Field { name: String, value: String },
    /// A file part's DATA begins at this absolute stream offset.
    FileStart {
        name: String,
        filename: String,
        data_offset: u64,
    },
    /// The file part's data ended at this absolute offset (exclusive).
    FileEnd { data_end: u64 },
    /// The closing boundary was read.
    End,
}

/// The caps the scanner enforces (from `translation_policy::MediaLimits`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Caps {
    pub text_field_max_bytes: usize,
    pub max_parts: usize,
}

#[derive(Debug)]
enum State {
    /// Expecting `\r\n--boundary` at the start of `pending`.
    Delimiter,
    /// After a delimiter: expecting `--` (end) or `\r\n` (a part follows).
    AfterDelimiter,
    /// Reading a part's header block.
    Headers,
    /// Inside a text part, accumulating its value.
    Text {
        name: String,
    },
    /// Inside a file part: searching for the next delimiter, dropping data.
    File,
    Done,
}

/// The streaming scanner. Feed it every chunk, in order, via [`Scanner::push`].
pub(crate) struct Scanner {
    delim: Vec<u8>,
    caps: Caps,
    state: State,
    pending: Vec<u8>,
    /// Absolute stream offset of `pending[0]`, plus `SKEW` (see below).
    base: u64,
    parts: usize,
}

/// The scanner prepends a virtual `\r\n` so the first delimiter has the same
/// `\r\n--boundary` shape as every other. Offsets it reports are `base + i - SKEW`.
const SKEW: u64 = 2;

/// The `boundary` parameter of a `Content-Type: multipart/form-data` header value.
///
/// # Errors
/// `Malformed` when the media type is not `multipart/form-data`, the boundary is absent,
/// repeated, too long or carries a character RFC 2046 does not allow.
pub(crate) fn boundary_of(content_type: &str) -> Result<String, ScanError> {
    let mut parts = content_type.split(';');
    let media = parts.next().unwrap_or("").trim();
    if !media.eq_ignore_ascii_case("multipart/form-data") {
        return Err(ScanError::Malformed(
            "content-type must be multipart/form-data",
        ));
    }
    let mut found: Option<String> = None;
    for p in parts {
        let Some((k, v)) = p.split_once('=') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case("boundary") {
            if found.is_some() {
                return Err(ScanError::Malformed("the multipart boundary is repeated"));
            }
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|r| r.strip_suffix('"'))
                .unwrap_or(v);
            found = Some(v.to_owned());
        }
    }
    let b = found.ok_or(ScanError::Malformed("the multipart boundary is missing"))?;
    let ok_char = |c: char| c.is_ascii_alphanumeric() || "'()+_,-./:=? ".contains(c);
    if b.is_empty() || b.len() > MAX_BOUNDARY_LEN || !b.chars().all(ok_char) || b.ends_with(' ') {
        return Err(ScanError::Malformed("the multipart boundary is not valid"));
    }
    Ok(b)
}

impl Scanner {
    /// A scanner for a body whose `Content-Type` is `content_type`.
    ///
    /// # Errors
    /// See [`boundary_of`].
    pub(crate) fn new(content_type: &str, caps: Caps) -> Result<Self, ScanError> {
        let boundary = boundary_of(content_type)?;
        let mut delim = b"\r\n--".to_vec();
        delim.extend_from_slice(boundary.as_bytes());
        Ok(Self {
            delim,
            caps,
            state: State::Delimiter,
            // The virtual CRLF the first delimiter's leading `\r\n` comes from.
            pending: b"\r\n".to_vec(),
            base: 0,
            parts: 0,
        })
    }

    /// Has the closing boundary been read?
    pub(crate) fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// Absolute offset of `pending[i]`.
    fn abs(&self, i: usize) -> u64 {
        self.base + i as u64 - SKEW
    }

    fn consume(&mut self, n: usize) {
        self.pending.drain(..n);
        self.base += n as u64;
    }

    /// Feed the next chunk; returns the events it completed.
    ///
    /// # Errors
    /// A [`ScanError`]; the scanner is unusable afterwards.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<Vec<Event>, ScanError> {
        let mut events = Vec::new();
        if matches!(self.state, State::Done) {
            // Epilogue after the closing boundary: ignored, like every parser does.
            return Ok(events);
        }
        self.pending.extend_from_slice(chunk);
        while self.step(&mut events)? {}
        Ok(events)
    }

    /// Signal end of stream.
    ///
    /// # Errors
    /// `Malformed` when the body ended before its closing boundary.
    pub(crate) fn finish(&self) -> Result<(), ScanError> {
        if self.is_done() {
            Ok(())
        } else {
            Err(ScanError::Malformed(
                "the multipart body ended before its closing boundary",
            ))
        }
    }

    /// One transition; `Ok(true)` when more can be made with the bytes at hand.
    fn step(&mut self, events: &mut Vec<Event>) -> Result<bool, ScanError> {
        match &self.state {
            State::Done => Ok(false),
            State::Delimiter => {
                let need = self.delim.len();
                let have = self.pending.len().min(need);
                if self.pending[..have] != self.delim[..have] {
                    return Err(ScanError::Malformed(
                        "the multipart body does not start with its boundary",
                    ));
                }
                if self.pending.len() < need {
                    return Ok(false);
                }
                self.consume(need);
                self.state = State::AfterDelimiter;
                Ok(true)
            }
            State::AfterDelimiter => {
                if self.pending.len() < 2 {
                    return Ok(false);
                }
                match &self.pending[..2] {
                    b"--" => {
                        self.consume(2);
                        self.state = State::Done;
                        events.push(Event::End);
                        Ok(false)
                    }
                    b"\r\n" => {
                        self.consume(2);
                        self.parts += 1;
                        if self.parts > self.caps.max_parts {
                            return Err(ScanError::TooManyParts);
                        }
                        self.state = State::Headers;
                        Ok(true)
                    }
                    _ => Err(ScanError::Malformed(
                        "a multipart boundary is followed by something other than CRLF or --",
                    )),
                }
            }
            State::Headers => {
                let Some(end) = find(&self.pending, b"\r\n\r\n") else {
                    if self.pending.len() > MAX_HEADER_BYTES {
                        return Err(ScanError::Malformed(
                            "a multipart part's headers are too large",
                        ));
                    }
                    return Ok(false);
                };
                if end > MAX_HEADER_BYTES {
                    return Err(ScanError::Malformed(
                        "a multipart part's headers are too large",
                    ));
                }
                let head = parse_part_headers(&self.pending[..end])?;
                self.consume(end + 4);
                match head.filename {
                    Some(filename) => {
                        events.push(Event::FileStart {
                            name: head.name,
                            filename,
                            data_offset: self.abs(0),
                        });
                        self.state = State::File;
                    }
                    None => self.state = State::Text { name: head.name },
                }
                Ok(true)
            }
            State::File => {
                if let Some(i) = find(&self.pending, &self.delim) {
                    events.push(Event::FileEnd {
                        data_end: self.abs(i),
                    });
                    self.consume(i + self.delim.len());
                    self.state = State::AfterDelimiter;
                    return Ok(true);
                }
                // Drop everything that cannot be the start of a delimiter. Keep a tail
                // one byte shorter than the delimiter.
                let keep = self.delim.len() - 1;
                if self.pending.len() > keep {
                    let drop = self.pending.len() - keep;
                    self.consume(drop);
                }
                Ok(false)
            }
            State::Text { name } => {
                let name = name.clone();
                if let Some(i) = find(&self.pending, &self.delim) {
                    if i > self.caps.text_field_max_bytes {
                        return Err(ScanError::FieldTooLarge);
                    }
                    let value = std::str::from_utf8(&self.pending[..i])
                        .map_err(|_| ScanError::Malformed("a multipart text field is not UTF-8"))?
                        .to_owned();
                    events.push(Event::Field { name, value });
                    self.consume(i + self.delim.len());
                    self.state = State::AfterDelimiter;
                    return Ok(true);
                }
                if self.pending.len() > self.caps.text_field_max_bytes + self.delim.len() {
                    return Err(ScanError::FieldTooLarge);
                }
                Ok(false)
            }
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

struct PartHead {
    name: String,
    filename: Option<String>,
}

/// Parse one part's header block. Only `Content-Disposition: form-data` and
/// `Content-Type` are accepted; anything that could make a provider read the part
/// differently (a transfer encoding, a folded header, an RFC 2231 extended parameter)
/// is refused.
fn parse_part_headers(block: &[u8]) -> Result<PartHead, ScanError> {
    let text = std::str::from_utf8(block)
        .map_err(|_| ScanError::Malformed("a multipart part header is not UTF-8"))?;
    let mut disposition: Option<&str> = None;
    for line in text.split("\r\n") {
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(ScanError::Malformed(
                "a folded multipart header is not accepted",
            ));
        }
        let Some((k, v)) = line.split_once(':') else {
            return Err(ScanError::Malformed("a multipart header line has no colon"));
        };
        let k = k.trim();
        if k.eq_ignore_ascii_case("content-disposition") {
            if disposition.is_some() {
                return Err(ScanError::Malformed(
                    "a multipart part repeats Content-Disposition",
                ));
            }
            disposition = Some(v.trim());
        } else if k.eq_ignore_ascii_case("content-transfer-encoding") {
            let v = v.trim();
            if !(v.eq_ignore_ascii_case("binary")
                || v.eq_ignore_ascii_case("7bit")
                || v.eq_ignore_ascii_case("8bit"))
            {
                return Err(ScanError::Malformed(
                    "a multipart part declares a content-transfer-encoding",
                ));
            }
        }
    }
    let disp = disposition.ok_or(ScanError::Malformed(
        "a multipart part has no Content-Disposition",
    ))?;
    let mut segs = split_params(disp)?.into_iter();
    if !segs
        .next()
        .is_some_and(|(k, v)| v.is_none() && k.eq_ignore_ascii_case("form-data"))
    {
        return Err(ScanError::Malformed("a multipart part is not form-data"));
    }
    let (mut name, mut filename) = (None, None);
    for (k, v) in segs {
        let k = k.to_ascii_lowercase();
        match (k.as_str(), v) {
            ("name", Some(v)) => {
                let repeated = name.replace(v).is_some();
                if repeated {
                    return Err(ScanError::Malformed("a multipart part repeats its name"));
                }
            }
            ("filename", Some(v)) => {
                let repeated = filename.replace(v).is_some();
                if repeated {
                    return Err(ScanError::Malformed(
                        "a multipart part repeats its filename",
                    ));
                }
            }
            (k, _) if k.ends_with('*') => {
                return Err(ScanError::Malformed(
                    "an RFC 2231 extended parameter is not accepted",
                ));
            }
            _ => {}
        }
    }
    let name = name.ok_or(ScanError::Malformed("a multipart part has no name"))?;
    if name.is_empty() || name.len() > 256 {
        return Err(ScanError::Malformed(
            "a multipart part name is empty or too long",
        ));
    }
    Ok(PartHead { name, filename })
}

/// Split `a; b="c;d"; e=f` into `[(a,None),(b,Some("c;d")),(e,Some("f"))]`, honouring
/// quoted strings and `\"` / `\\` escapes inside them.
fn split_params(s: &str) -> Result<Vec<(String, Option<String>)>, ScanError> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| *c == ' ' || *c == ';') {
            chars.next();
        }
        if chars.peek().is_none() {
            return Ok(out);
        }
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c == ';' {
                break;
            }
            key.push(c);
            chars.next();
        }
        let key = key.trim().to_owned();
        if chars.peek() == Some(&'=') {
            chars.next();
            let mut val = String::new();
            if chars.peek() == Some(&'"') {
                chars.next();
                let mut closed = false;
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => match chars.next() {
                            Some(e @ ('"' | '\\')) => val.push(e),
                            _ => {
                                return Err(ScanError::Malformed(
                                    "a bad escape in a multipart parameter",
                                ));
                            }
                        },
                        '"' => {
                            closed = true;
                            break;
                        }
                        c => val.push(c),
                    }
                }
                if !closed {
                    return Err(ScanError::Malformed(
                        "an unterminated quoted multipart parameter",
                    ));
                }
            } else {
                while let Some(&c) = chars.peek() {
                    if c == ';' {
                        break;
                    }
                    val.push(c);
                    chars.next();
                }
                val = val.trim().to_owned();
            }
            out.push((key, Some(val)));
        } else {
            out.push((key, None));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CT: &str = "multipart/form-data; boundary=XyZ123";
    const CAPS: Caps = Caps {
        text_field_max_bytes: 64,
        max_parts: 8,
    };

    fn body(parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
        let mut b = Vec::new();
        for (name, filename, data) in parts {
            b.extend_from_slice(b"--XyZ123\r\n");
            match filename {
                Some(f) => b.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                    )
                    .as_bytes(),
                ),
                None => b.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
                ),
            }
            b.extend_from_slice(data);
            b.extend_from_slice(b"\r\n");
        }
        b.extend_from_slice(b"--XyZ123--\r\n");
        b
    }

    fn scan(bytes: &[u8], chunk: usize) -> Result<Vec<Event>, ScanError> {
        let mut s = Scanner::new(CT, CAPS)?;
        let mut out = Vec::new();
        for c in bytes.chunks(chunk.max(1)) {
            out.extend(s.push(c)?);
        }
        s.finish()?;
        Ok(out)
    }

    #[test]
    fn fields_and_a_file_are_found_at_every_chunk_size_with_exact_offsets() {
        let data = b"line one\r\n--XyZ12 not a boundary\r\nline two";
        let b = body(&[
            ("purpose", None, b"batch"),
            ("file", Some("in.jsonl"), data),
            ("model", None, b"gpt-5"),
        ]);
        let start = find(&b, data).expect("data in body") as u64;
        for chunk in [1, 2, 3, 7, 64, b.len()] {
            let ev = scan(&b, chunk).unwrap_or_else(|e| panic!("chunk {chunk}: {e:?}"));
            assert_eq!(
                ev,
                vec![
                    Event::Field {
                        name: "purpose".into(),
                        value: "batch".into()
                    },
                    Event::FileStart {
                        name: "file".into(),
                        filename: "in.jsonl".into(),
                        data_offset: start
                    },
                    Event::FileEnd {
                        data_end: start + data.len() as u64
                    },
                    Event::Field {
                        name: "model".into(),
                        value: "gpt-5".into()
                    },
                    Event::End,
                ],
                "chunk size {chunk}"
            );
            // The offsets slice the original body to exactly the file's bytes.
            let (Event::FileStart { data_offset, .. }, Event::FileEnd { data_end }) =
                (&ev[1], &ev[2])
            else {
                panic!("shape");
            };
            assert_eq!(&b[*data_offset as usize..*data_end as usize], data);
        }
    }

    #[test]
    fn an_empty_file_and_a_binary_file_are_exact() {
        let bin: Vec<u8> = (0..=255u8).collect();
        let b = body(&[("file", Some("a.bin"), &bin), ("e", Some("e"), b"")]);
        let ev = scan(&b, 5).expect("scan");
        let ends: Vec<_> = ev
            .iter()
            .filter_map(|e| match e {
                Event::FileEnd { data_end } => Some(*data_end),
                _ => None,
            })
            .collect();
        assert_eq!(ends.len(), 2);
        let starts: Vec<_> = ev
            .iter()
            .filter_map(|e| match e {
                Event::FileStart { data_offset, .. } => Some(*data_offset),
                _ => None,
            })
            .collect();
        assert_eq!(&b[starts[0] as usize..ends[0] as usize], bin.as_slice());
        assert_eq!(starts[1], ends[1], "an empty file part has an empty range");
    }

    // ── The refusals: each is a parser-differential or a bound the guard must BLOCK. ──

    #[test]
    fn a_preamble_before_the_first_boundary_is_refused() {
        let mut b = b"junk\r\n".to_vec();
        b.extend(body(&[("model", None, b"x")]));
        assert!(matches!(scan(&b, 4096), Err(ScanError::Malformed(_))));
    }

    #[test]
    fn a_missing_closing_boundary_is_refused() {
        let b = body(&[("model", None, b"x")]);
        let cut = &b[..b.len() - 6];
        assert!(matches!(scan(cut, 4096), Err(ScanError::Malformed(_))));
    }

    #[test]
    fn a_text_field_over_the_cap_is_refused_even_without_a_delimiter() {
        let big = vec![b'a'; 4096];
        let b = body(&[("prompt", None, &big)]);
        assert_eq!(scan(&b, 100), Err(ScanError::FieldTooLarge));
        // The same bytes as a FILE are not a text field and are fine.
        assert!(scan(&body(&[("prompt", Some("p.txt"), &big)]), 100).is_ok());
    }

    #[test]
    fn too_many_parts_is_refused() {
        let parts: Vec<(&str, Option<&str>, &[u8])> =
            (0..9).map(|_| ("a", None, b"1".as_slice())).collect();
        assert_eq!(scan(&body(&parts), 64), Err(ScanError::TooManyParts));
    }

    #[test]
    fn extended_parameters_and_transfer_encodings_are_refused() {
        for head in [
            "Content-Disposition: form-data; name=\"file\"; filename*=UTF-8''x.jsonl",
            "Content-Disposition: form-data; name=\"a\"\r\nContent-Transfer-Encoding: base64",
            "Content-Disposition: form-data; name=\"a\"\r\nContent-Disposition: form-data; name=\"b\"",
            "Content-Disposition: attachment; name=\"a\"",
            "Content-Disposition: form-data; filename=\"only\"",
            "Content-Disposition: form-data; name=\"a\"\r\n folded: x",
        ] {
            let raw = format!("--XyZ123\r\n{head}\r\n\r\nv\r\n--XyZ123--\r\n");
            assert!(
                matches!(scan(raw.as_bytes(), 4096), Err(ScanError::Malformed(_))),
                "{head}"
            );
        }
    }

    #[test]
    fn a_boundary_followed_by_garbage_is_refused() {
        let raw =
            "--XyZ123\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--XyZ123X\r\n";
        assert!(matches!(
            scan(raw.as_bytes(), 4096),
            Err(ScanError::Malformed(_))
        ));
    }

    #[test]
    fn the_content_type_and_boundary_are_validated() {
        assert_eq!(
            boundary_of("multipart/form-data; boundary=abc").as_deref(),
            Ok("abc")
        );
        assert_eq!(
            boundary_of("multipart/form-data; boundary=\"a b\"").as_deref(),
            Ok("a b")
        );
        for bad in [
            "application/json",
            "multipart/form-data",
            "multipart/form-data; boundary=",
            "multipart/form-data; boundary=a; boundary=b",
            "multipart/form-data; boundary=a\r\nb",
            "multipart/form-data; boundary=\"a \"",
        ] {
            assert!(boundary_of(bad).is_err(), "{bad}");
        }
        let long = format!("multipart/form-data; boundary={}", "a".repeat(71));
        assert!(boundary_of(&long).is_err());
    }

    #[test]
    fn quoted_names_with_semicolons_and_escapes_parse() {
        let raw = "--XyZ123\r\nContent-Disposition: form-data; name=\"a;b\\\"c\"\r\n\r\nv\r\n--XyZ123--\r\n";
        let ev = scan(raw.as_bytes(), 3).expect("scan");
        assert_eq!(
            ev[0],
            Event::Field {
                name: "a;b\"c".into(),
                value: "v".into()
            }
        );
    }

    #[test]
    fn bytes_after_the_closing_boundary_are_an_ignored_epilogue() {
        let mut b = body(&[("model", None, b"x")]);
        b.extend_from_slice(b"--XyZ123\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nevil\r\n--XyZ123--\r\n");
        let ev = scan(&b, 7).expect("scan");
        assert_eq!(
            ev.iter()
                .filter(|e| matches!(e, Event::Field { .. }))
                .count(),
            1
        );
    }
}
