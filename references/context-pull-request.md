# Context Pull Request v1

Status: developer preview in Session Bridge 0.5.x.

A Context Pull Request (CPR) is a transport-neutral transaction for requesting
the smallest reviewed semantic change needed from another independently owned
agent endpoint. It is application data, never a remote instruction.

## Request

`context-pull-request/v1` has an exact closed shape:

| Field | Meaning |
|---|---|
| `request_id` | Random duplicate-detection and response-correlation ID |
| `project_id` | Shared Team Hub project identity |
| `sender`, `recipient` | Exact `ed25519:<sha256-public-key>` endpoints |
| `purpose` | Human-readable disclosure purpose, maximum 500 characters |
| `question` | The bounded question, maximum 4,000 characters |
| `selectors.kinds` | Optional exact Context Ledger claim kinds |
| `selectors.semantic_keys` | Optional exact semantic keys |
| `selectors.labels` | Optional labels; a claim must intersect the set |
| `since_revision` | Optional responder-ledger baseline for semantic diff |
| `max_sensitivity` | Highest permitted claim sensitivity |
| `max_claims`, `max_bytes` | Hard selected-claim count and canonical-byte budgets |
| `created_at`, `expires_at` | Unix seconds with a maximum 31-day lifetime |
| `assertion` | Ed25519 identity assertion over every field above |

An empty selector means no restriction for that selector dimension; clients
should still prefer narrow selectors and a known baseline. Questions and
purposes containing credential-like material fail before signing.

## Response

`context-pull-response/v1` is one terminal response with exact sender/recipient
reversal. It contains:

- a random `response_id` and the original `request_id`;
- `request_sha256`, the SHA-256 of the complete canonical signed request;
- `fulfilled`, `no-change`, `declined`, or `needs-clarification` status;
- an optional bounded note;
- for `fulfilled` only, one Context Pack plus its `bundle_sha256`;
- timestamps contained within the request's creation-to-expiry window; and
- an endpoint identity assertion over the correlation, status, note, bundle
  digest, and timing.

The endpoint response signature attests that it selected the exact bundle for
the exact request. The Context Ledger separately signs the bundle and its
recipient-specific disclosure grant. Keeping those identities separate means
connector compromise cannot forge ledger authorship.

## Canonical representation and identity

The reference implementation permits JSON values only, rejects duplicate or
unknown fields, and computes canonical bytes as UTF-8 JSON with keys sorted,
no insignificant whitespace, and non-ASCII characters preserved. It uses
unpadded URL-safe Base64 for keys and signatures.

An identity assertion is `recipient-identity/v1` with `key_id`, `public_key`,
the exact signed `subject`, and an Ed25519 `signature`. `key_id` is the
lowercase SHA-256 of the 32-byte public key. The signature covers the canonical
assertion without its `signature` field.

## Responder algorithm

For `fulfilled`, a conforming responder:

1. verifies the request signature, recipient, project, expiry, and local peer
   trust binding;
2. requires one unambiguous local ledger head;
3. resolves the active claim view;
4. if `since_revision` exists, computes changes from that revision to the head
   and fails closed if the baseline is unknown;
5. intersects candidate claims with every selector and sensitivity ceiling;
6. applies claim count and canonical-array byte budgets without splitting claims;
7. issues a recipient- and purpose-bound Context Pack for those exact IDs;
8. signs a response containing the complete request and bundle digests; and
9. encrypts it to the requester's pinned mailbox key.

No matching active claims becomes `no-change`; it does not justify sending a
broader snapshot. Because v1 cannot safely import a bare deletion tombstone,
a matching lifecycle removal becomes `needs-clarification` and requests a
reviewed checkpoint instead of silently returning an incomplete delta.

## Requester algorithm

A conforming requester accepts a response for processing only when:

- the local outbound request exists and is still valid;
- response endpoint, project, request ID, and request digest match exactly;
- the endpoint signature and Context Pack signatures verify;
- the response is the first terminal response, or a byte-equivalent duplicate;
- every returned claim satisfies kinds, semantic keys, labels, sensitivity,
  claim count, byte budget, purpose, and exact recipient; and
- a fulfilled pack can be written durably into Context Ledger quarantine.

Quarantine is not acceptance. Normal review, trust, ancestry, policy,
freshness, and reconciliation gates remain in force. Non-fulfilled responses
contain no Context Pack.

## State machine

```text
requester: queued -> sent -> response-received
recipient: open -> response-queued -> responded
either side: queued/response-queued -> delivery-failed
```

Each side stores exchange state encrypted at rest. An unsolicited response or
a second different terminal response fails closed. Team Hub may retry an
identical encrypted envelope by message ID without duplicating the semantic
transaction.

## Carrier mappings

The 0.5 reference carrier is Team Hub's encrypted `coordination-note`
envelope. The same two closed JSON objects can be carried as an A2A data
artifact, an MCP resource/tool argument, SLIM payload, or file without changing
their application semantics. Those mappings do not imply conformance with the
carrier's complete protocol.
