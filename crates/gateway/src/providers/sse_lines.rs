//! Byte-level line splitting for streamed provider responses (SSE and NDJSON).
//!
//! # Why this exists
//!
//! A network chunk boundary is NOT a character boundary. Every streaming
//! adapter used to decode each chunk on its own — `from_utf8(&chunk)?` in the
//! OpenAI, Anthropic and Gemini parsers, `from_utf8_lossy(&chunk)` in Cohere and
//! Azure — so a multi-byte character (`€`, `é`, any CJK text, an emoji) split
//! across two chunks either ENDED the stream with "non-UTF8 chunk" or was
//! replaced by two U+FFFD characters in the customer's output.
//!
//! The fix is to buffer BYTES and decode only a complete line. `\n` (0x0A) is
//! never part of a multi-byte UTF-8 sequence, so a line cut on it is always a
//! whole number of characters.

/// Accumulates raw chunk bytes and yields complete lines.
#[derive(Debug, Default)]
pub(crate) struct LineBuffer {
    buf: Vec<u8>,
    /// Bytes before this offset hold no `\n` — the next search starts here.
    scanned: usize,
}

impl LineBuffer {
    pub(crate) fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Bytes of the next complete line, without its `\n` and a trailing `\r`.
    fn next_line_bytes(&mut self) -> Option<Vec<u8>> {
        let rel = self.buf[self.scanned..].iter().position(|&b| b == b'\n');
        let Some(rel) = rel else {
            self.scanned = self.buf.len();
            return None;
        };
        let pos = self.scanned + rel;
        let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
        self.scanned = 0;
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Some(line)
    }

    /// The next complete line, decoded strictly.
    ///
    /// # Errors
    ///
    /// Fail-CLOSED on a complete line that is not UTF-8: the upstream sent
    /// bytes that are not text, and the caller ends the stream rather than
    /// guessing (the adapters' behaviour before this module, now applied per
    /// line instead of per chunk).
    pub(crate) fn next_line(&mut self) -> Option<Result<String, std::string::FromUtf8Error>> {
        self.next_line_bytes().map(String::from_utf8)
    }

    /// The next complete line, invalid bytes replaced with U+FFFD — for the
    /// adapters that were already lossy (Cohere, Azure).
    pub(crate) fn next_line_lossy(&mut self) -> Option<String> {
        self.next_line_bytes()
            .map(|l| String::from_utf8_lossy(&l).into_owned())
    }
}

/// Build a `reqwest::Response` whose body arrives as exactly these chunks —
/// the only way to put a chunk boundary inside a character in a test.
#[cfg(test)]
pub(crate) fn response_from_chunks(chunks: Vec<&'static [u8]>) -> reqwest::Response {
    let stream = futures::stream::iter(
        chunks
            .into_iter()
            .map(|c| Ok::<_, std::io::Error>(bytes::Bytes::from_static(c))),
    );
    reqwest::Response::from(axum::http::Response::new(reqwest::Body::wrap_stream(
        stream,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `€` is E2 82 AC. Cut it after its first two bytes.
    #[test]
    fn a_character_split_across_chunks_decodes_whole() {
        let mut lb = LineBuffer::default();
        lb.push(b"data: price \xE2\x82");
        assert!(lb.next_line().is_none(), "no newline yet");
        lb.push(b"\xAC5\r\ndata: next\n");
        assert_eq!(lb.next_line().unwrap().unwrap(), "data: price €5");
        assert_eq!(lb.next_line().unwrap().unwrap(), "data: next");
        assert!(lb.next_line().is_none());
    }

    #[test]
    fn lossy_path_keeps_a_split_character() {
        let mut lb = LineBuffer::default();
        lb.push("{\"text\":\"日".as_bytes().split_at(10).0);
        lb.push(&"{\"text\":\"日本\"}\n".as_bytes()[10..]);
        assert_eq!(lb.next_line_lossy().unwrap(), "{\"text\":\"日本\"}");
    }

    /// Must-reject twin: a complete line that is genuinely not UTF-8 is an
    /// error on the strict path, never silently accepted.
    #[test]
    fn a_complete_invalid_line_is_an_error() {
        let mut lb = LineBuffer::default();
        lb.push(b"data: \xFF\xFE\n");
        assert!(lb.next_line().unwrap().is_err());
    }

    #[test]
    fn many_lines_in_one_chunk_and_an_unterminated_tail() {
        let mut lb = LineBuffer::default();
        lb.push(b"a\n\nb\r\nc");
        assert_eq!(lb.next_line().unwrap().unwrap(), "a");
        assert_eq!(lb.next_line().unwrap().unwrap(), "");
        assert_eq!(lb.next_line().unwrap().unwrap(), "b");
        assert!(lb.next_line().is_none());
        lb.push(b"d\n");
        assert_eq!(lb.next_line().unwrap().unwrap(), "cd");
    }
}
