# Product boundary

Braid should be evaluated against one question: can independently owned existing agents exchange the smallest useful, verifiable context change and reconcile it without losing provenance or hiding conflicts?

## Owned

- session-to-claim extraction and review;
- semantic revisions and diffs;
- recipient/purpose/sensitivity-aware minimization;
- author signatures and exact disclosure grants;
- provenance, freshness, supersession, retraction, expiry, and revocation semantics;
- quarantine, trust-on-first-accept, policy rollback detection, and conflict-preserving merge;
- disclosure ledger and synchronized project-state summaries.
- ephemeral, encrypted, scope-bound coordination notes that never become durable context implicitly.
- asynchronous endpoint enrollment, opaque project mailboxes, offline delivery, and scheduled transport of already reviewed revisions;
- signed Context Pull Requests with exact recipient, purpose, selectors,
  baseline revision, sensitivity, claim/byte ceilings, terminal response
  correlation, and request-aware quarantine;

## External boundaries and deliberately unimplemented layers

- A2A discovery, task/message lifecycle, and conformant transport;
- MCP invocation and transport beyond the shipped local stdio surface;
- organization SSO identity and general cross-organization discovery (Team Hub ships a scoped enrolled-endpoint directory, not a universal agent directory);
- agent scheduling, delegation, workflow orchestration, and tool execution;
- generic email/chat/inbox experiences.

## Acceptance tests

A release should fail if it cannot demonstrate all of the following:

1. Exact semantic additions, removals, changes, and lifecycle transitions.
2. Recipient-specific exclusion with reviewable reasons and hard byte/claim budgets.
3. No credential sentinel in disclosed output.
4. Source provenance for every accepted claim.
5. Both sides retained for an unresolved semantic conflict.
6. Expired and revoked claims absent from the active view.
7. Signed recipient/scope/policy/expiry binding and tamper rejection.
8. Quarantine before acceptance and no imported command authority.
9. A complete signed disclosure crosses the A2A-shaped artifact boundary into quarantine, and MCP completes quarantine/review/accept over the same ledger.
10. A cross-process encrypted Context Pack round trip with replay/recovery behavior.
11. Receiver and relay reject a disclosure for another principal.
12. Review gating, unknown ancestry, policy rollback/equivocation, and a third independent head all fail before reachable state changes.
13. Concurrent agents keep isolated stages and cannot commit one another's staged context.
14. Pairing identities prove possession of persistent recipient keys and reject arbitrary principal aliases.
15. Reviewing a stage is read-only; approval binds an exact digest and a changed stage cannot commit.
16. Two heads cannot collapse without a current reconciliation plan that preserves or explicitly resolves every conflict.
17. A trusted endpoint can request a bounded semantic delta, the peer can
    answer asynchronously, and only matching claims enter receiver quarantine.
18. Tampered, expired, unsolicited, selector-expanding, over-budget, or
    differently duplicated Context Pull Responses fail closed.
