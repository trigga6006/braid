# Context Ledger v0.1

Context Ledger is Session Bridge's owned semantic layer. Transports may change; the lifecycle and invariants below must not.

## Unit of change

A claim has an immutable identifier, typed kind, statement, semantic key, lifecycle status, confidence, freshness window, provenance, sensitivity, audience, supersession/conflict links, and redaction labels.

Supported kinds are fact, decision, constraint, hypothesis, question, action, blocker, and disagreement. Effective statuses are active, superseded, retracted, expired, and revoked.

Confirmed claims require non-human evidence. Provenance identifies a bounded URI, observed time, source type, and optional SHA-256; transcript extraction uses a redacted event/span locator and hashes rather than retaining raw source text.

## Revision

A `context-pack/v0.1` revision is canonical JSON containing:

- pack/scope identity and purpose;
- revision ID, parents, sequence, and time;
- authors and governance;
- claims and artifact references;
- a canonical SHA-256 integrity value.

Parent graphs are bounded, acyclic, and sequence checked. A revision never mutates after commit. Lifecycle resolution produces a view without rewriting earlier revisions.

## Disclosure

Planning is recipient-specific and fail-closed:

1. remove expired, superseded, revoked, over-clearance, out-of-audience, and secret-scanner-blocked claims;
2. score remaining claims by task kind and purpose relevance;
3. enforce claim/byte budgets and explicit required claims;
4. return inclusion/exclusion reasons for review;
5. create a minimized derivative revision;
6. sign an export and non-delegable grant bound to the exact recipient, project, scope, policy digest/version, source digest, and expiry.

Issuance is recorded per recipient and claim. “Who has this?” means a disclosure was issued; offline delivery cannot be proven unless a transport adds an acknowledgement. Revocation is forward-looking and cannot erase a recipient's prior copy.

## Import and reconciliation

Every received pack is untrusted data. Strict structure, digest, signature, grant, expiry, and policy checks happen before quarantine. The receiving ledger persists one local principal and rejects disclosures addressed to any other principal. Reviewing exposes the actual claims and is durably recorded before acceptance; credential findings require a separate explicit override. Acceptance is an explicit trust decision and still grants no command/tool authority.

The disclosure grant issuer must be the signed export author; unrelated keys cannot split content authorship from disclosure authorization. Untrusted local import reads are capped before JSON allocation. Multi-file state transitions write a hash-chained prepare record first. A prepare-only crash is recovered only when action-specific state proves no durable mutation occurred; malformed, partially applied, or ambiguous audit tails make later mutation fail closed.

Stages are isolated by random stage ID. `review-staged` validates and displays a stage without mutating approval state. `approve-staged` records the exact returned digest; commit recomputes it and fails if any reviewed field changed. This prevents parallel agents from overwriting or consuming one another's work and makes review an inspect-then-approve action rather than a ceremonial command. Imports may create at most two heads; a third independent head remains quarantined until existing heads are reconciled. Unknown-parent revisions, recipient replay, stale or equivocating remote policy, and changed trusted keys fail before the revision becomes reachable ledger state.

Reconciliation auto-combines disjoint or byte-equivalent semantic claims. Divergent active claims with the same semantic key create a durable unresolved conflict containing both sides. With exactly two heads, `reconcile` persists a one-use plan bound to those heads and returns its token. A merge commit requires that token and requires every conflict either to remain a `disagreement` claim or to be explicitly superseded by a provenance-linked resolution covering all conflicting claim IDs. Stale tokens and ordinary commits cannot collapse divergent heads.

The receiver identity is a persistent Ed25519 key shared by the network bridge and all ledgers under one state root. Recipient principals are derived from the public key; an optional configured principal is only an equality pin. This prevents a disclosure recipient from being replaced by an arbitrary local label, while leaving human/organization directory mapping to a future control plane.

## Standard boundaries

- A Context Pull Request is a transport-neutral, signed query over reviewed
  ledger state. Its response attests to the exact selected Context Pack digest,
  but still enters receiver quarantine. It does not create shared mutable
  memory, grant command authority, or bypass reconciliation.
- The shipped A2A-shaped adapter carries the complete signed disclosure and grant as one data Artifact and crosses into receiver quarantine in tests. It does not implement or claim conformance with A2A discovery, tasks, messages, or transports.
- The shipped MCP stdio adapter exposes closed-schema tools for the full quarantine/review/accept lifecycle over the same ledger. MCP owns invocation/session transport.
- External directories and message fabrics could locate principals and carry bytes, but no AGNTCY/SLIM integration is shipped. They do not own Context Ledger state.
- Session Bridge's temporary encrypted relay is one transport implementation, not the portable semantic contract.
