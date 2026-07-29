<div align="center">

![Braid - existing sessions, shared context](assets/braid-og.png)

# Braid

**Governed context synchronization for agents that already exist.**

[![Security tests](https://github.com/trigga6006/braid/actions/workflows/security-tests.yml/badge.svg)](https://github.com/trigga6006/braid/actions/workflows/security-tests.yml)
![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Claude Code + Codex + Hermes](https://img.shields.io/badge/Claude_Code_%E2%86%94_Codex_%E2%86%94_Hermes-111827)

</div>

Braid connects existing Claude Code, Codex, Nous Hermes Agent, and OpenClaw sessions locally or across the public internet. Its Context Ledger turns useful session state into typed, provenance-linked, versioned claims; minimizes those claims for a named recipient; signs and encrypts the disclosure; then quarantines and reconciles it at the other end without silently choosing a winner.

For teams, the self-hosted Team Hub adds durable asynchronous mailboxes. Developers no longer need to start a temporary room at the same time: an endpoint connector can queue an approved Context Pack, the blind hub can retain its ciphertext while a teammate is offline, and the teammate's next sync places it into the existing Context Ledger quarantine. An optional always-on project agent can receive separately addressed checkpoints and produce scheduled project summaries.

Version 0.5 adds **Context Pull Requests**: a trusted agent can ask another endpoint for a bounded semantic change (for example, decisions and blockers since a known revision). The answer is signed, correlated to the exact request, constrained by kind/label/sensitivity/claim/byte ceilings, encrypted in transit, and quarantined on receipt. It is context review between sovereign agents, not a shared mutable brain.

It is built for the handoff that a ticket cannot capture: the research, decisions, constraints, rejected paths, tests, uncertainty, and open questions still living inside independent agent threads.

## The boundary

Braid is not another generic agent protocol, tool bus, directory, or orchestrator.

| Layer | Braid position |
|---|---|
| [A2A](https://a2a-protocol.org/v0.3.0/specification/) | A tested A2A-shaped data Artifact carries one complete signed disclosure and grant. Braid does not implement or claim conformance with A2A discovery, tasks, messages, or transports. |
| [MCP](https://modelcontextprotocol.io/specification/) | A local stdio server exposes the full ledger quarantine/review/accept lifecycle as closed-schema tools/resources. MCP owns invocation and transport, not context semantics. |
| [AGNTCY / SLIM](https://docs.agntcy.org/) | No integration is shipped. Those projects address directory, identity, messaging, and observability; Braid does not claim those capabilities. |
| Scoped coordination | The temporary encrypted bridge includes short-lived task-scoped notes for questions and acknowledgements. Notes are not ledger state and cannot bypass signed disclosure acceptance. |
| Team Hub | A self-hosted blind store-and-forward layer owns enrollment, project membership, public mailbox keys, opaque queues, receipts, and retention. It cannot read or merge Context Packs. |
| Context Pull Request | A signed recipient-bound ask and terminal response select the smallest useful semantic delta. The request is data, never remote command authority. |
| Context Ledger | Owns extraction, semantic revisions, recipient minimization, disclosure grants, provenance, freshness, conflicts, quarantine, and the who-was-issued-what audit. |

The durable unit is a context change, not a chat message:

```text
session -> extract -> review -> approve -> commit -> diff -> minimize -> sign -> encrypt
        -> quarantine -> verify -> reconcile -> supersede / expire / revoke
```

## Install

Ask either agent to install the skill for your user account:

```text
Install the Braid skill from https://github.com/trigga6006/braid for my user account.
```

Manual skill locations:

| Product | User skill path |
|---|---|
| Codex / ChatGPT | `~/.codex/skills/braid` |
| Claude Code | `~/.claude/skills/braid` |
| Nous Hermes Agent | `~/.hermes/skills/braid` |
| OpenClaw | `~/.openclaw/skills/braid` |

For the packaged developer CLIs:

```bash
python -m pip install "git+https://github.com/trigga6006/braid.git"
```

This installs the unified `braid` command plus its direct sub-binaries `braid-session`, `braid-ledger`, `braid-net`, `braid-hub`, `braid-team`, and `braid-mcp`. Every group is reachable through the umbrella:

```bash
braid handoff --from "<session>" --project "<ledger-project>"   # local one-step handoff
braid session <list|resolve|export|ask|doctor>                  # local session discovery
braid ledger <...>                                              # Context Ledger lifecycle
braid incident <ask|brief|status>                               # on-call incident handoff
braid team <...>                                                # Team Hub endpoint connector
braid net <...>                                                 # temporary paired room
braid hub <...>                                                 # self-hosted Team Hub
braid mcp --project "<project>"                                 # stdio MCP server
```

The skill can also run its checked-in scripts directly with `python "<skill-dir>/scripts/braid_cli.py" <group> ...`, so a global package install is optional.

### OpenClaw

OpenClaw sessions are discoverable, exportable, and resumable like any other surface, and OpenClaw can drive the Context Ledger over MCP.

Register the ledger server in `~/.openclaw/openclaw.json`:

```json
{
  "mcp": {
    "servers": {
      "braid": { "command": "braid", "args": ["mcp", "--project", "<ledger-project>"] }
    }
  }
}
```

Then verify discovery:

```bash
braid session doctor
braid session list --provider openclaw
```

Because OpenClaw's own CLI redacts message text, Braid reads its per-agent SQLite store directly and read-only — no Gateway required. Two behaviors to know: the zero-ceremony `handoff` accepts only `operator` and `talk` sessions, since `channel`, `cron`, and `spawn` sessions carry turns authored elsewhere; and a live turn runs `openclaw agent --session-key … --json` without `--deliver`, so the reply comes back to Braid rather than being broadcast to the session's channels. See [references/surfaces.md](references/surfaces.md) for the full contract.

### Nous Hermes Agent

Hermes is a first-class Braid surface: its sessions are discoverable, exportable, and resumable exactly like Codex and Claude ones, and it can drive the full Context Ledger over MCP.

Install the skill and register the MCP server:

```bash
hermes skills install https://github.com/trigga6006/braid
python -m pip install "git+https://github.com/trigga6006/braid.git"
```

Then add the ledger server to `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  braid:
    command: "braid"
    args: ["mcp", "--project", "<ledger-project>"]
```

Without the package install, point the same entry at the checked-in script instead — `command: "python"`, `args: ["<skill-dir>/scripts/braid_cli.py", "mcp", "--project", "<ledger-project>"]`.

Verify the wiring, which reports the Hermes home, whether `state.db` is present, and how many sessions are readable:

```bash
braid session doctor
braid session list --provider hermes
```

Three Hermes-specific behaviors are worth knowing before you rely on them:

- Message text is exported through `hermes sessions export --format trace`, so the `hermes` executable must be on `PATH`, and Hermes' own secret redaction runs before anything reaches the ledger.
- **Live Hermes turns are refused.** `hermes -z` auto-bypasses tool approvals and offers no verified tools-disabled mode, so `session ask --provider hermes` deliberately does not run. Read-only `session export` and `handoff` are unaffected.
- **The zero-ceremony handoff is first-party only.** Hermes stores Telegram, Discord, Slack, web-UI, and cron conversations in the same local database, and those turns are remote-authored. `handoff` accepts `cli` and `tui` sessions and refuses the rest, pointing at the governed path.

See [references/surfaces.md](references/surfaces.md) for the full contract.

## Fastest agent workflow

Host:

```text
Use Braid as host. Catch my agent up with my teammate's agent about <scope>. Exchange relevant thread context, reconcile conflicts, and keep watching until both sides have the same final summary.
```

Join:

```text
Use Braid as joiner with this code: <private code>. The scope is <scope>. Share relevant context from this thread and stay in the loop until both sides are synchronized.
```

Both humans compare one six-digit safety code through a trusted side channel. That approval opens a temporary, task-scoped collaboration; it does not authorize commands, deployments, file changes, purchases, or unrelated disclosure.

## Context Ledger

Each installation creates one persistent, key-derived recipient identity automatically. Extract candidates from an existing local session, inspect the exact stage, approve its digest, and then commit it:

```bash
braid ledger --project phoenix extract --session "<session-id>" --provider codex --stage
braid ledger --project phoenix review-staged <stage-id>
braid ledger --project phoenix approve-staged <stage-id> --review-digest <sha256:digest>
braid ledger --project phoenix commit --author "alice" --stage-id <stage-id>
```

`review-staged` is deliberately read-only; it displays the claims and returns a digest. `approve-staged` binds approval to that exact digest, and `commit` rechecks it. Concurrent agents receive separate stage IDs, so one agent cannot overwrite or commit another agent's staged context. To stage an already inspected claims file, use `stage --claims candidates.json`, then run the same review and approval steps. State defaults to `~/.braid`; set `BRAID_HOME` for an isolated workspace. Global `--home <path>` is for standalone ledger tests; a paired bridge and ledger must share the same `BRAID_HOME` so they use the same recipient identity. Project ledgers persist until the user applies their own retention policy.

The extractor blocks credential-shaped events, redacts common PII, ignores prompt-injection-shaped instructions, suppresses low-signal acknowledgements, and stores source hashes/spans rather than raw transcript text as provenance.

Inspect the current state:

```bash
braid ledger --project phoenix status
braid ledger --project phoenix log
braid ledger --project phoenix diff <before-revision> <after-revision>
braid ledger --project phoenix freshness
braid ledger --project phoenix verify
```

Preview a recipient-minimized plan without sending:

```bash
braid ledger --project phoenix plan \
  --recipient "<peer-ed25519-principal-from-status>" \
  --purpose "API migration handoff" \
  --max-sensitivity internal
```

Create an exact recipient-bound signed disclosure:

```bash
braid ledger --project phoenix export <revision> \
  --recipient "<peer-ed25519-principal-from-status>" \
  --purpose "API migration handoff" \
  --output bob-context.json
```

At the receiver, the ledger automatically uses that installation's persistent recipient key. Verification still produces quarantine, not authority:

```bash
braid ledger --project phoenix import bob-context.json
braid ledger --project phoenix review-import <token>
braid ledger --project phoenix accept <token>
braid ledger --project phoenix reconcile --local <revision> --remote <revision>
```

`import` only verifies and quarantines; it returns `reviewed: false` and the exact `review-import` next step. Acceptance is unavailable until that separate command revalidates and displays the redacted review.

`status` reports the local `ed25519:<key-id>` principal. The optional global `--principal` flag is an expected-identity pin, not an alias: any value other than the endpoint's key-derived principal is rejected. A disclosure for one endpoint cannot be promoted by a different endpoint even if it obtains the signed file.

Divergent active claims with the same semantic key remain a durable unresolved conflict. With two heads, `reconcile` returns a one-use `reconciliation_token` and the exact conflict set. Pass that token to `resolve --claims <file> --message <reason> --reconciliation-token <token>`, then review, approve, and commit the resulting stage. Every conflict must be retained as a `disagreement` claim or explicitly superseded with provenance; a normal commit cannot collapse two heads.

## Always-on self-hosted Team Hub

Team Hub is the asynchronous team mode. It is deliberately a layer beside an issue tracker, knowledge base, or context graph—not a replacement. The server routes ciphertext and maintains project membership; endpoint connectors and Context Ledgers retain all plaintext semantics.

Copy `.env.example` to `.env`, select the initial team and project, then start a local hub:

```bash
docker compose up -d --build
```

The Compose service runs as an unprivileged user with a read-only root filesystem, a persistent `/data` volume, dropped Linux capabilities, a health check, and a host port fixed to `127.0.0.1`. Team and project bootstrap is idempotent. Show its state and audit integrity:

```bash
docker compose exec team-hub braid hub --data-dir /data status
docker compose exec team-hub braid hub --data-dir /data verify
```

On a VPS, keep the published port on loopback and put an HTTPS reverse proxy or managed private ingress in front of it. Set `BRAID_HUB_PUBLIC_URL=https://bridge.example.com` before creating enrollment codes. Do not expose the Compose HTTP port directly to the public internet.

Create one private, short-lived enrollment code per endpoint:

```bash
docker compose exec team-hub braid hub --data-dir /data enrollment \
  --team Omni --project default --label Alice --role member
```

Use `--role project-agent` for an optional always-on project librarian. Transfer the code privately and enroll the endpoint through a temporary file:

```bash
braid team enroll --project omni --code-file enrollment-code.txt
braid team directory --project omni
braid team status --project omni
```

Delete the code file immediately after enrollment. Every subsequent API request proves possession of the endpoint's persistent Ed25519 key and includes a timestamp and one-use nonce. Server responses are signed by the server identity pinned in the enrollment code.

Before sending context to a teammate for the first time, compare their displayed `ed25519:<key-id>` principal through an already trusted channel, then approve it once:

```bash
braid team trust --project omni --principal "ed25519:<key-id>"
```

Never approve an endpoint from its editable label alone. Each directory mailbox key carries the endpoint's own Ed25519 signature, and local trust pins that signed key binding plus its project role. A new endpoint or changed role remains `untrusted` or `changed` until explicitly approved; outgoing publication fails closed and incoming envelopes from that endpoint are rejected before quarantine. Use `untrust` to remove a local approval.

Ask for a bounded update without requesting a transcript. Put the question in a temporary file so it does not appear in the process list:

```bash
braid team request \
  --project omni \
  --to "ed25519:<peer-key-id>" \
  --purpose "authentication handoff" \
  --question-file question.txt \
  --kind decision \
  --kind blocker \
  --label backend \
  --since-revision <last-seen-revision> \
  --max-sensitivity internal \
  --max-claims 20

braid team sync --project omni --ledger-project omni
```

Delete `question.txt` after queuing. The peer's next sync returns the request without placing it in the Context Ledger. The peer can inspect every inbound/outbound exchange and answer, decline, or request clarification:

```bash
braid team requests --project omni
braid team respond \
  --project omni \
  --ledger-project omni \
  --request-id <request-id> \
  --status fulfilled
braid team sync --project omni --ledger-project omni
```

`respond` selects only matching active claims within the signed ceilings and queues one terminal response. Its output lists the exact selected claim IDs before the next `sync` sends it. A fulfilled answer is independently signed by the responding endpoint and by its Context Ledger, and the requester still receives only a quarantine token. `declined`, `needs-clarification`, and `no-change` responses contain no Context Pack. A matching lifecycle removal returns `needs-clarification` rather than silently presenting a partial delta; send a reviewed checkpoint until signed deletion tombstones are added to the protocol.

### Standing authorization

Answering a trusted peer's recurring questions does not have to keep a person in the loop. A per-project standing authorization lets an endpoint answer the requests it covers, unattended:

```bash
braid team policy \
  --project omni --enable \
  --allowed-peers "ed25519:<peer-key-id>" \
  --allowed-kinds decision blocker constraint \
  --max-sensitivity internal \
  --max-claims 25 \
  --max-responses-per-hour 12

braid team auto-respond --project omni --ledger-project omni --dry-run
braid team run --project omni --ledger-project omni --auto-respond
```

It is a ceiling, never a widening. Automation is disabled by default, upgrades land disabled, an unknown policy field is an error rather than a no-op, and an unparsable policy fails the project closed. Enabling requires an explicit peer list and at least one allowed kind — an empty list means "nothing", so trusting a new endpoint for ordinary exchange never also grants it unattended pull authority. Automation only ever *answers* — it never accepts inbound context, resolves a conflict, approves a stage, or publishes a head.

These always refer to a human regardless of policy: divergent heads or unresolved conflicts, restricted sensitivity, a secret-scanner finding anywhere in scope, raw transcript provenance, context the request did not structurally ask for, and a lifecycle removal inside the requested window. `restricted` can never be authorized — the ceiling is capped at `confidential`.

The decision is bound to the payload, not to a preview: it is re-evaluated inside the responder's lock against the exact claims about to be signed, so a commit landing mid-flight cannot widen an authorized answer.

Every decision is appended to `<home>/team-autopolicy/<alias>.jsonl` with its reasons, recording claim identifiers and counts but never claim text. Referred requests stay `open` and remain answerable exactly as before. See [references/team-hub.md](references/team-hub.md) for the full gate list.

An agent still uses `braid ledger` to extract, review, approve, and commit context. After that review gate, it can publish the current head separately to every teammate or only to project agents:

```bash
braid team publish \
  --project omni \
  --ledger-project omni \
  --audience project-agents \
  --purpose "12-hour project checkpoint" \
  --max-sensitivity internal

braid team sync --project omni --ledger-project omni
```

`publish` is revision-aware: unchanged heads are not resent to the same recipient. Each recipient receives a distinct signed disclosure and X25519/HKDF/ChaCha20-Poly1305 mailbox envelope. Incoming packs are verified and placed into ledger quarantine; transport synchronization never accepts or merges them.

Run a lightweight connector continuously or on a 12-hour schedule:

```bash
braid team run \
  --project omni \
  --ledger-project omni \
  --interval-seconds 43200 \
  --publish-head \
  --audience project-agents
```

The long-running connector survives temporary network and Hub outages with bounded exponential backoff, preserves its encrypted outbox across restarts, and resumes the normal interval after a successful sync. This automates transport of already reviewed ledger state. It does not scrape raw Claude or Codex transcripts, silently approve a new stage, resolve divergent heads, or wake a vendor application that is no longer running. The next active agent task reviews quarantined changes, accepts or reconciles them, and starts with the updated project state.

An administrator can immediately disable a lost or compromised endpoint:

```bash
docker compose exec team-hub braid hub --data-dir /data endpoint \
  --principal "ed25519:<key-id>" --status disabled
```

See [the Team Hub architecture and trust boundary](references/team-hub.md) and the [competitive product map](references/product-map.md).

## Public internet bridge

Local discovery/export downloads nothing. Public joining needs pinned `cryptography` if it is not already available. Public hosting additionally uses a pinned, checksum-verified Cloudflare Tunnel helper; a managed HTTPS tunnel can be supplied instead. There is no Braid account, DNS change, router configuration, or API key.

Prepare only the role you need:

```bash
python scripts/braid_cli.py net setup --role host
python scripts/braid_cli.py net setup --role host --yes
```

Each side proves possession of a persistent Ed25519 recipient key during pairing. The key-derived principal is bound to the room, ephemeral exchange key, peer, and expiry; arbitrary self-asserted labels are not accepted. After safety-code approval, `status` shows both principals. Export to the displayed remote principal, then send the signed bundle with `share`:

```bash
python scripts/braid_cli.py net share --id <room-or-connection-id> --bundle-file bob-context.json
python scripts/braid_cli.py net watch --id <room-or-connection-id> --wait 45 --json
```

The relay rejects a disclosure addressed to anyone other than the approved channel peer. Signed context events are authenticated before relay, application-encrypted in transit, and remain untrusted until imported into the matching receiver-principal ledger's quarantine. A saved JSON `watch` response containing exactly one context-pack event can be passed directly to `braid import`.

## Interoperability

[`context-pull-request/v1`](references/context-pull-request.md) is a closed,
transport-neutral signed request/response format. Team Hub carries it today;
the semantic object can later ride A2A, MCP, or SLIM without making Session
Bridge another transport protocol.

`scripts/context_adapters.py` maps a complete `context-disclosure/v1` bundle to one strict A2A-shaped data Artifact with MIME type `application/vnd.braid.context-disclosure+json;version=1`. Its test crosses the artifact boundary into receiver quarantine and acceptance. It deliberately creates no task lifecycle and is not a claim of full A2A conformance.

`braid mcp --project <name>` exposes the same ledger as a line-delimited MCP stdio server. It enforces MCP initialize/initialized lifecycle and JSON-RPC ID rules. Its closed-schema tools include stage/review/approval/commit, live conflict and freshness resources, and import quarantine/review/accept; the adapter adds no second database or context representation. An optional `--principal <ed25519:id>` pins the expected local endpoint identity.

## Security properties

- X25519, HKDF-SHA-256, and ChaCha20-Poly1305 for temporary network channels.
- Ed25519 persistent author identities protected by Windows DPAPI, macOS Keychain, Linux Secret Service, or a restricted local fallback.
- Signed exports and non-delegable grants bound to exact recipient, project, scope, policy digest/version, parent digest, and expiry; both relay and receiver enforce the configured recipient.
- Strict JSON shape/depth/size limits, duplicate-key rejection, credential scanning, PII redaction, request limits, and replay counters.
- Crash-safe request retransmission prevents an accepted request with a lost response from desynchronizing the channel or duplicating a side effect.
- Append-only hash-chained audit, exact claim disclosure records, freshness states, revocation tombstones, and quarantine-first imports.
- State transitions write a hash-chained intent before multi-file mutation. A prepare-only crash is recovered only when action-specific state proves no durable mutation occurred; partial or ambiguous transitions keep audit verification failed closed.
- The bundled tunnel helper is release- and SHA-256-pinned. Arbitrary `cloudflared` binaries found on `PATH` are not executed implicitly.
- Team Hub enforces one-use enrollment, endpoint-signed requests and mailbox-key bindings, local peer/role pinning, replay nonces, signed server responses, project membership, bounded concurrency and socket lifetimes, request limits, per-mailbox count/byte quotas, endpoint and IP rate limits, idempotent message IDs, ciphertext expiry, acknowledgement-time payload erasure, and a hash-chained server audit.

Read [SECURITY.md](SECURITY.md) and [the network security model](references/network-mode.md) before using sensitive material.

## Verification and benchmarks

```bash
python -m pip install --requirement requirements.txt
ruff check scripts tests benchmarks
ruff format --check scripts tests benchmarks
python -m compileall -q scripts benchmarks tests
python -m unittest discover -s tests -v
python -m benchmarks.product_benchmark --out benchmark-results
python -m benchmarks.lifecycle_benchmark --iterations 3 --out benchmark-results/lifecycle.json
python -m benchmarks.team_hub_benchmark --messages 250 --workers 16 --out benchmark-results/team-hub.json
python -m benchmarks.context_quality.runner --engine reference --holdout-seed 20260722 --out benchmark-results/context-contract
python -m pip install --no-deps .
braid --help
```

The product benchmark invokes the real extractor, semantic model, recipient planner, signing, quarantine, import, and conflict logic. It records required-context recall, low-signal suppression, compression, latency, peak Python allocation during extraction, conflict preservation, and signed round-trip gates. The lifecycle benchmark separately measures 10/100/500-claim stage-review-approve-commit-export-quarantine-review-accept latency, peak Python allocation, and signed bundle size. The Team Hub benchmark concurrently writes opaque envelopes through the transactional mailbox, pages and acknowledges them, and verifies audit integrity. Adapter, receiver-replay, MCP lifecycle, review-gate, ancestry, rollback, head-bound, and encrypted retransmission behavior are covered by the test suite rather than the product benchmark. The separate context-quality harness is a protocol contract and adversarial evaluator; its `reference` engine is an oracle, not a product score.

See the checked-in [benchmark baselines](benchmarks/BASELINE.md) for reproducible commands, environment, results, and measurement limits.

CI runs lint and format checks, compilation, the full suite, all three benchmark surfaces, and package installation on Windows, macOS, and Ubuntu with Python 3.11 and 3.13. Separate Ubuntu jobs audit the pinned runtime dependency, build/check the wheel and self-testing source distribution, and boot the hardened Docker image against its health, status, and audit endpoints.

## Release status and honest limits

Version `0.5.x` is an open-source developer preview suitable for controlled team pilots, not a claim of SOC 2 readiness, guaranteed availability, or bug-free production use.

- Quick Tunnels provide convenience, not an enterprise SLA.
- Endpoint compromise defeats confidentiality for context that endpoint may read.
- Revocation cannot erase a copy already delivered; it prevents future local use/re-sharing and records intent.
- Pairing principals are cryptographic endpoint pseudonyms with proof of key possession, not verified human or organization identities. Context authors are pinned on explicit first acceptance. Enterprise SSO/directory mapping, centralized lifecycle policy, transparency logging, retention enforcement, and compliance exports remain future control-plane work.
- Agents cannot wake after their application ends a turn. The skill keeps the active turn watching while both agents are running.
- Team Hub is a single-node SQLite service. It has durable offline mailboxes but no high-availability failover, server-side SSO, or multi-region replication.
- Automatic extraction is deterministic and conservative, not an infallible semantic model. Review remains mandatory before commit/disclosure.

Apache-2.0 licensed. Contributions and security reports are welcome.
