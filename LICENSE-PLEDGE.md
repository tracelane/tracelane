<!-- tracelane:classification: PUBLIC -->
# Tracelane Apache 2.0 License Pledge

## What is enforceable, whether or not you trust us

Every release published under Apache 2.0 is licensed to you perpetually and
irrevocably by the license itself (Apache License 2.0, §2–3). Nothing we do
later reaches code that has already been released: not a license change on
future releases, not an acquisition, not us going away. Those grants were made
by the license, not by whoever owns the project this year, so they survive a
change of ownership.

That is the part you can rely on without taking our word for anything. If you
are evaluating Tracelane for a codebase you have to support for a decade, this
paragraph is the one that matters.

## What we commit to, as maintainers

This is a statement of intent, not a contract. There is no counterparty, no
consideration, no governing law and no court that will enforce it — it is worth
what our reputation is worth. We put it in writing so that changing course would
be a visible, dated broken promise rather than a quiet edit:

1. Tracelane stays Apache 2.0 for the life of the project under our stewardship.
2. We will not relicense the core to Commons Clause, the Business Source License
   (BSL), the Server-Side Public License (SSPL), the Elastic License v2 (ELv2),
   or any other license that restricts use as a hosted or managed service.
3. We will not use the license to restrict commercial use, seats, or deployment
   of the Apache 2.0 core.

## The honest carve-out on point 3

Point 3 is about the *license*. It is not a claim that the tree contains no
feature flags — it does.

Four guardrail rails are gated on a per-tenant entitlement flag: **R2**
(secrets/PII), **R5** (format), **R6** (system-prompt leak) and **R7**
(topic/competitor). On our hosted service those flags follow your plan. With no
control plane — an OSS self-host — they resolve to the free tier and those four
rails do not run. The other rails are ungated and always run: R1 (cost),
R3 (tool safety, schema + definition pinning), R4 (lethal trifecta) and
R8 (prompt injection). The gate lives in
[`crates/gateway/src/guardrail/rail.rs`](crates/gateway/src/guardrail/rail.rs);
each rail declares its own `feature()`.

All of that code is Apache 2.0. You may fork it and delete the checks — the
license permits it, and we will never use the license, a patent claim, or a
terms-of-service clause to stop you. What we are pledging is the license, not
the absence of flags.

## If ownership changes

A new owner may license *new* code however they choose, and this pledge does not
bind them. No unilateral pledge binds a future owner — there is no CLA,
foundation or trust standing behind it, and we would rather say so than imply a
protection that does not exist. What survives a sale is the Apache 2.0 grant on
everything already released.

---

*Signed: Sanjeev Kumar Singh, Founder, Tracelane — April 2026*
*Last updated: 2026-08-07*
