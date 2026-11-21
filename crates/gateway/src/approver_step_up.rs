//! ACT-41: approving a held call needs a recent sign-in (`specs/ACT-41-approver-step-up.md`).
//!
//! Pure decision, no I/O, no `crate::` paths: compiled into the binary (`main.rs`) and into
//! `lib.rs`, so `cargo test -p gateway --lib approver_step_up` runs it without linking the
//! gateway test binary. The caller supplies the verified credential and the reference-table
//! window; this file only decides.

/// What the gateway verified about the approver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credential {
    /// A WorkOS access token whose signature was re-verified; `auth_time` is its signed claim
    /// (seconds since the epoch of the last ACTIVE sign-in — a silent refresh does not move it).
    WorkosSession { auth_time: Option<i64> },
    /// The single-tenant self-host master key: the operator's only credential, no IdP.
    SelfHostOperator,
    /// The debug-build dev stub (no `WORKOS_CLIENT_ID`): no real identity at all.
    DevStub,
    /// Anything else (tenant API key, mTLS). Cannot hold the approve capability today.
    Other,
}

/// The decision for an approve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Signed in recently enough; the value is the claim to record with the decision.
    Fresh { auth_time: i64 },
    /// No identity provider to step up against; the decision proceeds and records no time.
    Exempt,
    /// Refuse: the approver must sign in again.
    ReauthRequired,
}

/// Decide an approve.
///
/// `now` and `auth_time` are Unix seconds; `max_age_secs` is the freshness window and
/// `skew_secs` the tolerance for an issuer clock ahead of ours.
///
/// # Errors
/// None — the result is a verdict. Fail-CLOSED: a missing, non-positive, too-old or
/// too-far-future `auth_time`, a negative window, and any credential other than a verified
/// session or the self-host operator all yield [`Verdict::ReauthRequired`]. The dev stub is
/// exempt only when `debug_build` is true (callers pass `cfg!(debug_assertions)`).
#[must_use]
pub fn verdict(
    credential: Credential,
    now: i64,
    max_age_secs: i64,
    skew_secs: i64,
    debug_build: bool,
) -> Verdict {
    match credential {
        Credential::SelfHostOperator => Verdict::Exempt,
        Credential::DevStub if debug_build => Verdict::Exempt,
        Credential::DevStub | Credential::Other => Verdict::ReauthRequired,
        Credential::WorkosSession { auth_time: None } => Verdict::ReauthRequired,
        Credential::WorkosSession {
            auth_time: Some(at),
        } => {
            if at <= 0 || max_age_secs < 0 || skew_secs < 0 {
                return Verdict::ReauthRequired;
            }
            // Checked arithmetic: a hostile claim near i64::MAX must not wrap into "fresh".
            let too_future = at.checked_sub(now).is_none_or(|ahead| ahead > skew_secs);
            let too_old = now.checked_sub(at).is_none_or(|age| age > max_age_secs);
            if too_future || too_old {
                Verdict::ReauthRequired
            } else {
                Verdict::Fresh { auth_time: at }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Credential as C, Verdict as V, verdict};

    const NOW: i64 = 1_790_000_000;
    const WIN: i64 = 900;
    const SKEW: i64 = 30;

    fn s(at: Option<i64>) -> C {
        C::WorkosSession { auth_time: at }
    }
    fn v(c: C) -> V {
        verdict(c, NOW, WIN, SKEW, false)
    }

    // ── Positive ──────────────────────────────────────────────────────────────
    #[test]
    fn p1_fresh_now() {
        assert_eq!(v(s(Some(NOW))), V::Fresh { auth_time: NOW });
    }
    #[test]
    fn p2_fresh_one_minute() {
        assert_eq!(
            v(s(Some(NOW - 60))),
            V::Fresh {
                auth_time: NOW - 60
            }
        );
    }
    #[test]
    fn p3_fresh_just_inside() {
        assert!(matches!(v(s(Some(NOW - 899))), V::Fresh { .. }));
    }
    #[test]
    fn p4_fresh_exact_window() {
        assert!(matches!(v(s(Some(NOW - WIN))), V::Fresh { .. }));
    }
    #[test]
    fn p5_future_within_skew() {
        assert!(matches!(v(s(Some(NOW + 1))), V::Fresh { .. }));
    }
    #[test]
    fn p6_future_exact_skew() {
        assert!(matches!(v(s(Some(NOW + SKEW))), V::Fresh { .. }));
    }
    #[test]
    fn p7_self_host_operator_exempt() {
        assert_eq!(v(C::SelfHostOperator), V::Exempt);
        assert_eq!(
            verdict(C::SelfHostOperator, NOW, WIN, SKEW, true),
            V::Exempt
        );
    }
    #[test]
    fn p8_dev_stub_exempt_in_debug_only() {
        assert_eq!(verdict(C::DevStub, NOW, WIN, SKEW, true), V::Exempt);
    }
    #[test]
    fn p9_short_window_fresh() {
        assert!(matches!(
            verdict(s(Some(NOW - 59)), NOW, 60, SKEW, false),
            V::Fresh { .. }
        ));
    }
    #[test]
    fn p10_fresh_returns_the_claim_not_now() {
        assert_eq!(
            v(s(Some(NOW - 123))),
            V::Fresh {
                auth_time: NOW - 123
            }
        );
    }
    #[test]
    fn p11_zero_skew_accepts_exact_now() {
        assert!(matches!(
            verdict(s(Some(NOW)), NOW, WIN, 0, false),
            V::Fresh { .. }
        ));
    }

    // ── Negative ──────────────────────────────────────────────────────────────
    #[test]
    fn n1_stale_one_second_past() {
        assert_eq!(v(s(Some(NOW - WIN - 1))), V::ReauthRequired);
    }
    #[test]
    fn n2_stale_one_day() {
        assert_eq!(v(s(Some(NOW - 86_400))), V::ReauthRequired);
    }
    #[test]
    fn n3_missing_claim() {
        assert_eq!(v(s(None)), V::ReauthRequired);
    }
    #[test]
    fn n4_future_beyond_skew() {
        assert_eq!(v(s(Some(NOW + SKEW + 1))), V::ReauthRequired);
    }
    #[test]
    fn n5_future_one_day() {
        assert_eq!(v(s(Some(NOW + 86_400))), V::ReauthRequired);
    }
    #[test]
    fn n6_zero_claim() {
        assert_eq!(v(s(Some(0))), V::ReauthRequired);
    }
    #[test]
    fn n7_negative_claim() {
        assert_eq!(v(s(Some(-5))), V::ReauthRequired);
    }
    #[test]
    fn n8_api_key_or_other() {
        assert_eq!(v(C::Other), V::ReauthRequired);
        assert_eq!(verdict(C::Other, NOW, WIN, SKEW, true), V::ReauthRequired);
    }
    #[test]
    fn n10_dev_stub_in_release() {
        assert_eq!(v(C::DevStub), V::ReauthRequired);
    }
    #[test]
    fn n11_zero_window_refuses_one_second() {
        assert_eq!(
            verdict(s(Some(NOW - 1)), NOW, 0, SKEW, false),
            V::ReauthRequired
        );
    }
    #[test]
    fn n12_min_claim() {
        assert_eq!(v(s(Some(i64::MIN))), V::ReauthRequired);
    }
    #[test]
    fn n13_max_claim_does_not_wrap() {
        assert_eq!(v(s(Some(i64::MAX))), V::ReauthRequired);
        assert_eq!(
            verdict(s(Some(i64::MAX)), i64::MIN, WIN, SKEW, false),
            V::ReauthRequired
        );
    }
    #[test]
    fn n14_negative_now_cannot_make_old_fresh() {
        assert_eq!(
            verdict(s(Some(1)), i64::MIN, WIN, SKEW, false),
            V::ReauthRequired
        );
    }
    #[test]
    fn n15_negative_window_or_skew_fail_closed() {
        assert_eq!(
            verdict(s(Some(NOW)), NOW, -1, SKEW, false),
            V::ReauthRequired
        );
        assert_eq!(
            verdict(s(Some(NOW)), NOW, WIN, -1, false),
            V::ReauthRequired
        );
    }
    #[test]
    fn n16_zero_skew_refuses_one_second_future() {
        assert_eq!(
            verdict(s(Some(NOW + 1)), NOW, WIN, 0, false),
            V::ReauthRequired
        );
    }

    // ── Invariant sweep ───────────────────────────────────────────────────────
    #[test]
    fn invariant_sweep() {
        let offsets = [
            i64::MIN,
            -86_400,
            -(WIN + 1),
            -WIN,
            -WIN + 1,
            -60,
            -1,
            0,
            1,
            SKEW - 1,
            SKEW,
            SKEW + 1,
            86_400,
            i64::MAX,
        ];
        let mut checked = 0;
        for debug in [false, true] {
            for win in [0, 1, 60, WIN, 3_600] {
                for skew in [0, SKEW] {
                    for now in [NOW, 1, i64::MAX / 2] {
                        let mut creds = vec![
                            C::SelfHostOperator,
                            C::DevStub,
                            C::Other,
                            s(None),
                            s(Some(0)),
                        ];
                        creds.extend(offsets.iter().map(|o| s(now.checked_add(*o))));
                        for c in creds {
                            checked += 1;
                            match verdict(c, now, win, skew, debug) {
                                V::Fresh { auth_time } => {
                                    // Fresh only for a verified session with that exact claim,
                                    // inside the window, not beyond the skew.
                                    assert_eq!(c, s(Some(auth_time)));
                                    assert!(auth_time > 0);
                                    assert!(now - auth_time <= win, "{c:?} {now} {win}");
                                    assert!(auth_time - now <= skew, "{c:?} {now} {skew}");
                                }
                                V::Exempt => assert!(
                                    c == C::SelfHostOperator || (c == C::DevStub && debug),
                                    "{c:?} exempt"
                                ),
                                V::ReauthRequired => {
                                    assert_ne!(c, C::SelfHostOperator);
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(checked > 1_000, "sweep covered {checked}");
    }
}
