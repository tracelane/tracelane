//! RI-06 / B-449 — spans lost at the JetStream boundary, counted exactly.
//!
//! A span the `TRACELANE_SPANS` stream removes at its limits (`max_age`, `max_bytes`
//! with `DiscardPolicy::Old`), by an operator delete, or by `max_deliver` exhaustion
//! was already ACKED to the publisher and is never delivered to ingest — so until this
//! module nothing counted it (ADR-077 Part II C17-ingest). The stream sequence is the
//! only witness: a single pull consumer receives FIRST deliveries in stream order, so a
//! skipped sequence is a message that was gone before delivery.
//!
//! Two questions, both pure (no I/O — the consumer loop feeds it):
//! - **at boot**: did the stream trim past what this durable had acked while ingest was
//!   down? `first_sequence > ack_floor + 1` says yes, and the gap is exact.
//! - **steady state**: did a first delivery skip a sequence? Redeliveries
//!   (`delivered > 1`) arrive out of order by design and never move the cursor.
//!
//! **Across a restart the "first deliveries arrive in order" premise has a hole**
//! (found 2026-09-21, B-493 run 3): messages the OLD process had received but not acked
//! are redelivered to the NEW one with `delivered = 2`, which `observe` ignores, while
//! the first genuinely new message arrives with `delivered = 1` — so a cursor started at
//! the ack floor jumped straight over the in-flight range and declared it a `Trim` of
//! 4,000 spans that all landed minutes later. The cursor therefore starts at the highest
//! sequence the durable has EVER been delivered (`consumer.info().delivered`), never at
//! the ack floor alone; a real boot trim is still `first_sequence > ack_floor + 1`.
//!
//! `stream.info().state.num_deleted` is NOT this counter: it counts interior holes; a
//! head trim advances `first_sequence` and leaves none.

/// One detected episode of loss, inclusive bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub first_missing: u64,
    pub last_missing: u64,
    pub kind: GapKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapKind {
    /// Found at boot: the durable's ack floor is below the stream's first retained
    /// message — everything in between was trimmed while ingest was not consuming.
    BootTrim,
    /// Found in flight: a first delivery skipped one or more stream sequences.
    Trim,
}

impl Gap {
    /// Spans lost in this episode.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.last_missing - self.first_missing + 1
    }
}

/// Continuity cursor over stream sequences of FIRST deliveries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapTracker {
    /// `None` until the first first-delivery when the boot read failed
    /// ([`Self::unanchored`]): the first message then SETS the cursor and counts nothing,
    /// because a tracker that does not know where the stream started must not call the
    /// stream's first retained message a gap.
    cursor: Option<u64>,
}

impl GapTracker {
    /// Build the tracker from the consumer's acked prefix and the stream's first retained
    /// sequence, returning the boot gap if there is one.
    ///
    /// `ack_floor == 0` is a brand-new durable: messages trimmed before it existed were
    /// never its responsibility (the 2026-09-12 recreation shape) and are NOT counted —
    /// stated here rather than hidden. Otherwise a gap exists iff
    /// `first_sequence > ack_floor + 1`; the cursor starts at the last sequence that is
    /// acked, retained, or already DELIVERED to this durable (`last_delivered_stream_seq`,
    /// the in-flight range a restart will see again as redeliveries), whichever is highest.
    #[must_use]
    pub fn at_boot(
        ack_floor_stream_seq: u64,
        first_sequence: u64,
        last_delivered_stream_seq: u64,
    ) -> (Self, Option<Gap>) {
        // The last sequence accounted for: acked, delivered-but-unacked (redelivered
        // after a restart with `delivered > 1`, which `observe` ignores by design), or
        // (when the stream's oldest retained message is newer than both) the one just
        // below that oldest message.
        let cursor = Some(
            ack_floor_stream_seq
                .max(last_delivered_stream_seq)
                .max(first_sequence.saturating_sub(1)),
        );
        let gap = if ack_floor_stream_seq > 0 && first_sequence > ack_floor_stream_seq + 1 {
            Some(Gap {
                first_missing: ack_floor_stream_seq + 1,
                last_missing: first_sequence - 1,
                kind: GapKind::BootTrim,
            })
        } else {
            None
        };
        (Self { cursor }, gap)
    }

    /// Observe one delivered message. Returns the gap it revealed, if any.
    ///
    /// Only a FIRST delivery (`delivered == 1`) can reveal a gap and only a first delivery
    /// moves the cursor; a redelivery is an older sequence coming back and says nothing
    /// about the head. A first delivery at or below the cursor (cannot happen on an ordered
    /// pull consumer, but a tracker must not panic on it) is ignored.
    #[must_use]
    pub fn observe(&mut self, stream_seq: u64, delivered: i64) -> Option<Gap> {
        if delivered != 1 {
            return None;
        }
        let Some(cursor) = self.cursor else {
            // Unanchored: this first delivery anchors the tracker. Nothing before it can
            // be judged, so nothing is counted.
            self.cursor = Some(stream_seq);
            return None;
        };
        if stream_seq <= cursor {
            return None;
        }
        let gap = if stream_seq > cursor + 1 {
            Some(Gap {
                first_missing: cursor + 1,
                last_missing: stream_seq - 1,
                kind: GapKind::Trim,
            })
        } else {
            None
        };
        self.cursor = Some(stream_seq);
        gap
    }

    /// A tracker whose boot read (`consumer.info()` / `stream.info()`) failed: the first
    /// first-delivery anchors it silently. Fail-OPEN — detection degrades to "from the
    /// first message on", never to a false gap and never to a stopped consumer.
    #[must_use]
    pub const fn unanchored() -> Self {
        Self { cursor: None }
    }

    /// The last first-delivered (or boot-resolved) stream sequence; 0 while unanchored.
    /// Read by the tests (the consumer loop needs only `observe`); kept public so a
    /// future `/health`-style probe from ingest can report it.
    #[cfg(test)]
    #[must_use]
    pub fn cursor(&self) -> u64 {
        self.cursor.unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contiguous_first_deliveries_reveal_nothing() {
        let (mut t, boot) = GapTracker::at_boot(3, 4, 0);
        assert_eq!(
            boot, None,
            "first retained = ack_floor + 1: nothing was trimmed"
        );
        assert_eq!(t.observe(4, 1), None);
        assert_eq!(t.observe(5, 1), None);
        assert_eq!(t.observe(6, 1), None);
        assert_eq!(t.cursor(), 6);
    }

    #[test]
    fn a_skipped_sequence_is_a_gap_with_exact_bounds() {
        let (mut t, _) = GapTracker::at_boot(3, 4, 0);
        assert_eq!(t.observe(4, 1), None);
        // 5, 6 and 7 never arrive; 8 does.
        let gap = t.observe(8, 1).expect("a skip is a gap");
        assert_eq!(
            gap,
            Gap {
                first_missing: 5,
                last_missing: 7,
                kind: GapKind::Trim
            }
        );
        assert_eq!(gap.count(), 3);
        assert_eq!(t.cursor(), 8);
    }

    #[test]
    fn a_redelivery_never_counts_and_never_moves_the_cursor() {
        let (mut t, _) = GapTracker::at_boot(3, 4, 0);
        assert_eq!(t.observe(4, 1), None);
        assert_eq!(t.observe(5, 1), None);
        // 4 comes back after a Nak (delivered = 2): out of order by design.
        assert_eq!(t.observe(4, 2), None);
        assert_eq!(t.cursor(), 5, "a redelivery must not rewind the cursor");
        // A redelivery of something far ahead of the cursor is not a gap either.
        assert_eq!(t.observe(40, 3), None);
        assert_eq!(t.cursor(), 5);
        assert_eq!(
            t.observe(6, 1),
            None,
            "the next first delivery is contiguous"
        );
    }

    /// B-493 run 3 (2026-09-21): ingest restarted with 4,000 messages delivered but
    /// unacked (ack_floor 14780, delivered up to 18780, stream first_sequence 1). The
    /// new process saw message 18781 first (`delivered = 1`) while 14781..18780 came
    /// back as redeliveries — and a cursor started at the ack floor called that range
    /// a 4,000-span `Trim` that never happened (all 4,000 landed). The cursor must start
    /// at the highest sequence ever delivered; a real trim is still detected.
    #[test]
    fn a_restart_with_in_flight_unacked_messages_is_not_a_loss() {
        let (mut t, boot) = GapTracker::at_boot(14780, 1, 18780);
        assert_eq!(
            boot, None,
            "nothing was trimmed: first_sequence 1 <= ack_floor + 1"
        );
        // Redeliveries of the in-flight range: ignored, no gap.
        assert_eq!(t.observe(14781, 2), None);
        assert_eq!(t.observe(18780, 2), None);
        // The first genuinely new message: contiguous with what was delivered, no gap.
        assert_eq!(t.observe(18781, 1), None);
        assert_eq!(t.cursor(), 18781);
        // …and a real skip after that IS still a gap.
        assert_eq!(
            t.observe(18785, 1),
            Some(Gap {
                first_missing: 18782,
                last_missing: 18784,
                kind: GapKind::Trim
            })
        );
    }

    #[test]
    fn a_brand_new_durable_counts_nothing_at_boot() {
        let (t, boot) = GapTracker::at_boot(0, 50, 0);
        assert_eq!(
            boot, None,
            "ack_floor 0: trimmed history was never this durable's"
        );
        assert_eq!(
            t.cursor(),
            49,
            "the cursor starts just below the first retained message"
        );
    }

    #[test]
    fn a_trim_past_the_ack_floor_is_a_boot_gap_with_exact_bounds() {
        // Acked through 3, then the stream trimmed to 19 while ingest was down:
        // 4..=18 are gone, 15 spans.
        let (t, boot) = GapTracker::at_boot(3, 19, 0);
        assert_eq!(
            boot,
            Some(Gap {
                first_missing: 4,
                last_missing: 18,
                kind: GapKind::BootTrim
            })
        );
        assert_eq!(boot.as_ref().map(Gap::count), Some(15));
        assert_eq!(t.cursor(), 18);
    }

    #[test]
    fn an_ack_floor_ahead_of_the_first_retained_message_is_not_a_gap() {
        // Normal healthy shape: the stream still holds messages older than the floor.
        let (t, boot) = GapTracker::at_boot(100, 40, 0);
        assert_eq!(boot, None);
        assert_eq!(
            t.cursor(),
            100,
            "the cursor is the acked prefix, not the older retained tail"
        );
    }

    #[test]
    fn an_unanchored_tracker_anchors_on_its_first_delivery_and_counts_nothing() {
        let mut t = GapTracker::unanchored();
        assert_eq!(t.cursor(), 0);
        assert_eq!(
            t.observe(500, 1),
            None,
            "the first message is the anchor, not a gap of 499"
        );
        assert_eq!(t.cursor(), 500);
        // From here on it is a normal tracker.
        assert_eq!(t.observe(501, 1), None);
        assert_eq!(t.observe(504, 1).map(|g| g.count()), Some(2));
    }

    #[test]
    fn a_first_delivery_at_or_below_the_cursor_is_ignored_not_a_panic() {
        let (mut t, _) = GapTracker::at_boot(10, 11, 0);
        assert_eq!(t.observe(10, 1), None);
        assert_eq!(t.observe(3, 1), None);
        assert_eq!(t.cursor(), 10);
    }
}
