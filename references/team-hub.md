# Team Hub architecture

- [Components](#components)
- [Trust boundary](#trust-boundary)
- [Server records](#server-records)
- [Delivery semantics](#delivery-semantics)
- [Context Pull Requests](#context-pull-requests)
- [Automation policy](#automation-policy)
- [Normal team lifecycle](#normal-team-lifecycle)
- [Operate a single-node Hub](#operate-a-single-node-hub)
- [Deliberate first-release limits](#deliberate-first-release-limits)

Team Hub turns Braid's temporary peer exchange into an asynchronous,
self-hosted team substrate. It complements an issue tracker, knowledge graph,
or company knowledge base; it does not replace one. The canonical durable unit
remains the signed Context Ledger disclosure.

## Components

1. **Endpoint connector** runs beside Claude Code or Codex. It owns the
   endpoint identity, mailbox decryption key, local Context Ledger, outbox,
   quarantine, and sync cursor.
2. **Team Hub** runs on a laptop, private server, or VPS. It owns project
   membership, one-time enrollment, the public-key directory, opaque durable
   mailboxes, acknowledgements, retention, and an audit log.
3. **Project agent** is optional. It is an enrolled endpoint on an always-on
   machine, receives only disclosures explicitly addressed to it, and may
   produce scheduled signed summaries. It is not part of the trusted relay.

Alice and Bob never need to be online together. A connector can upload an
approved disclosure, the hub can hold it while Bob is offline, and Bob's
connector can quarantine it during the next sync.

## Trust boundary

The initial hub is a blind store-and-forward service:

- endpoint Ed25519 keys authenticate every request;
- a separate persistent X25519 mailbox key encrypts each payload to exactly
  one enrolled recipient;
- each endpoint signs its own project/server/mailbox-key binding, and senders
  pin that binding and the intended project role after one out-of-band
  principal comparison;
- the inner Context Pack remains author-signed, recipient-bound, scoped,
  policy-bound, and expiring;
- the hub sees routing metadata, sizes, timing, and membership, but not Context
  Pack plaintext;
- receipt at the hub is not acceptance by a Context Ledger;
- remote data never gains tool or workflow authority;
- a project agent can read only packs separately exported and encrypted to its
  own endpoint principal.

TLS remains mandatory on a non-loopback network. Application encryption limits
the impact of relay compromise, while TLS protects request metadata and the
directory from passive network observers. A reverse proxy or managed ingress
may terminate TLS for the first self-hosted release.

## Server records

The hub uses one transactional SQLite database for a single-node deployment:

- teams and projects;
- endpoints and project memberships;
- one-use, high-entropy enrollment grants stored only as hashes;
- endpoint signing and mailbox public keys;
- opaque mailbox messages with unique sender-selected message IDs;
- acknowledgements and bounded delivery metadata;
- recently used request nonces;
- an append-only hash-chained administrative and delivery audit.

SQLite keeps `docker compose up` and laptop hosting lightweight. A future
Postgres storage adapter may implement the same protocol for high availability;
it must not introduce another representation of Context Ledger state.

## Delivery semantics

1. An administrator creates a project and a short-lived enrollment code.
2. The endpoint proves possession of its Ed25519 key and binds a mailbox X25519
   public key to that principal.
3. A sender fetches the enrolled project directory over an authenticated
   request, verifies every endpoint-signed mailbox binding, and sends only to
   entries approved in its local trust store.
4. The sender validates that the Context Pack is addressed to the selected
   recipient, encrypts it to that endpoint's mailbox key, and uploads an opaque
   envelope.
5. Retrying the same message ID and digest is idempotent. Reusing the ID with a
   different envelope fails closed.
6. A receiver authenticates, pulls a bounded page, decrypts locally, verifies
   the inner disclosure, and writes it to Context Ledger quarantine.
7. Only after durable local quarantine does the connector acknowledge the
   message. The hub then erases its ciphertext while retaining a minimal
   receipt according to policy.

## Context Pull Requests

A `context-pull-request/v1` is a signed application payload containing the
exact sender, recipient, project, purpose, question, optional baseline
revision, typed selectors, sensitivity ceiling, claim/byte budgets, and
expiry. Team Hub sees only the encrypted envelope metadata.

The recipient verifies the endpoint signature and local trust binding before
storing the request as protected exchange state. A request never enters the
Context Ledger and never authorizes a command. The responding connector may
select only active claims matching the signed request and, when a baseline is
present, only the semantic changes after that revision. An unavailable
baseline fails closed rather than expanding into a full snapshot.

A `context-pull-response/v1` is terminal and correlated to the exact locally
recorded request. `fulfilled` carries one recipient-bound Context Pack and its
signed digest; `no-change`, `declined`, and `needs-clarification` carry no
pack. The requester rechecks selectors and ceilings, rejects unsolicited or
different duplicate responses, and quarantines a valid fulfilled pack through
the normal ledger import boundary. See
[Context Pull Request v1](context-pull-request.md) for the closed object shapes
and verification algorithms.

## Automation policy

Automation has two distinct jobs:

- **Transport automation** may continuously or periodically deliver approved
  outbox entries and quarantine valid inbound entries.
- **Context creation** remains governed. Agents may be instructed to create an
  end-of-task checkpoint, but a background process must not scrape and publish
  raw vendor transcripts. Exact stage review and digest approval remain the
  default disclosure gate.

A team policy may later allow low-sensitivity, in-scope claims to use a durable
pre-authorization. Credential findings, raw transcripts, unrelated context,
restricted sensitivity, scope expansion, and semantic conflict always stop for
review.

## Normal team lifecycle

- On project start, the active agent pulls accepted project changes and sees a
  semantic diff from its previous checkpoint.
- During work, material decisions or findings become reviewed local revisions.
- At task end, the agent exports recipient-minimized packs into the connector
  outbox.
- The connector delivers while peers are online or offline.
- Every 12 hours, or on another configured schedule, connectors sync transport
  state. An optional project agent also reconciles its accepted inputs and
  publishes a signed digest.
- A new agent task starts from the latest accepted local revision, not by
  granting the server access to the entire private transcript.

## Operate a single-node Hub

Use the checked-in Compose stack for a laptop or one VPS. It fixes the host
listener to loopback, runs the image without root or Linux capabilities, keeps
the root filesystem read-only, persists `/data`, and restarts the service after
host reboots. Put an HTTPS reverse proxy, private overlay, or managed ingress in
front of loopback on a VPS. Never publish the internal HTTP listener directly.

Run `status` and `verify` as health and integrity checks. Run `purge` from a
daily scheduler to erase expired ciphertext and old receipts. The service also
purges opportunistically during normal mailbox operations.

The connector's `run` command is suitable for a process supervisor or endpoint
scheduler. It retries transient failures with bounded exponential backoff,
preserves protected outbox entries across restarts, pulls all bounded pages,
and resumes the configured interval after success. Only use `--publish-head`
where team policy permits transport of a changed, already reviewed revision.

Back up the complete Hub data volume, not only `hub.sqlite3`, because
`server-identity.json` is the identity pinned by enrolled endpoints. For a
simple consistent snapshot, stop the Compose service, archive the named
`braid-hub-data` volume with an operator-controlled backup tool, then
restart it. Encrypt backups, restrict access, test restoration on an isolated
host, and run `verify` after restore. Restoring the database without the same
server identity makes existing endpoint pins fail closed.

Before upgrading, take a tested snapshot and retain the previous image. The
Hub refuses an unknown schema version rather than guessing a migration. This
release has one schema and no live multi-node migration path.

## Deliberate first-release limits

- single-node SQLite service rather than high availability;
- no server-side plaintext search, embedding, or knowledge graph;
- no implicit organization-wide recipient or group key;
- no automatic trust in newly listed endpoints or changed project roles;
- no automatic resolution of semantic conflicts;
- no promise that a closed vendor application can be awakened;
- no standing-policy engine for automatically answering recurring requests;
- no SSO mapping until endpoint enrollment and the cryptographic protocol are
  proven in controlled team pilots.
