# Product map

This map is a product and architecture assessment, not a claim that any
individual mechanism is patentably novel. It reflects the public product and
protocol documentation reviewed on 2026-07-22.

## Executive position

The broad category - agents sharing memory or messages - is crowded. Session
Bridge should not lead with that claim. Its strongest position is narrower:

> A Context Pull Request lets one independently owned, already-running agent
> ask another for the smallest evidence-backed semantic change needed for a
> purpose, receive a signed recipient-specific answer, and place it into
> quarantine without silently accepting it or erasing disagreement.

That makes Braid a collaboration-governance layer. It can use A2A,
MCP, SLIM, HTTP, files, or Team Hub as carriage; it should not compete to own
those transports. It can import from memory systems; it should not become
another vector database or shared mutable brain.

## Category map

| Category / example | What it primarily owns | Meaningful overlap | Braid separation | Product decision |
|---|---|---|---|---|
| [A2A](https://a2a-protocol.org/v0.3.0/specification/) | Agent discovery, tasks, messages, artifacts, streaming, and push | Agent-to-agent exchange and data artifacts | Braid owns the governed semantic change before and after carriage: minimization, recipient grants, quarantine, revision ancestry, and conflict preservation | Integrate as an artifact/profile; do not rebuild tasks or discovery |
| [MCP](https://modelcontextprotocol.io/specification/2025-06-18/architecture) | Host/client/server invocation of tools, resources, and prompts | A model can invoke ledger and exchange operations | MCP deliberately does not define an application's memory or acceptance policy | Keep the local MCP surface; publish Context Pull Request schemas as portable application data |
| [AGNTCY SLIM](https://docs.agntcy.org/messaging/slim-core/), [Directory](https://docs.agntcy.org/dir/overview/) and [Identity](https://docs.agntcy.org/identity/identity/) | Secure messaging, routing, discovery, identity, and observability | Encrypted delivery and principal discovery | Braid is the semantic payload and receiver-governance layer | Offer a carrier adapter later; do not create a universal directory |
| [Claude Code agent teams](https://code.claude.com/docs/en/agent-teams) | Same-product spawned teammates, shared tasks, direct messages, and mailboxes | Developer agents coordinating with automatic message delivery | Braid connects existing independently owned cross-vendor sessions and preserves a durable governed context history outside one vendor runtime | Position as cross-runtime project memory governance, not a better subagent API |
| [OpenAI Agents SDK sessions](https://openai.github.io/openai-agents-python/sessions/) and [handoffs](https://openai.github.io/openai-agents-python/handoffs/) | History inside an application and delegation among agents in one runtime | Shared session state and handoff | Braid crosses separate owners, runtimes, machines, and trust boundaries | Supply an integration, not an alternative runtime |
| [Portable Agent Memory](https://github.com/santhoshravindran7/portable-agent-memory), [UMP](https://universalmemoryprotocol.io/), and [MMP](https://meshcognition.org/spec/mmp/) | Portable, typed, signed, or peer-to-peer memory protocols | Very high overlap in portable records, provenance, signatures, scope, and admission | Braid adds a concrete two-sided collaboration transaction: bounded ask, sender-side selection, signed correlated answer, recipient quarantine, disclosure ledger, and explicit disagreement lifecycle | Treat these as the closest protocol peers; build import/export and conformance fixtures instead of claiming the whole memory layer |
| [Hydrate](https://gethydrate.dev/) | Shared cross-runtime memory and peer pairing | Cross-agent, cross-runtime project context | Braid favors immutable recipient-specific disclosures and semantic conflicts over a common mutable project brain | Compete on governance and auditability, not setup convenience alone |
| [Snipara Project Brain](https://www.snipara.com/shared-context-claude-code-cursor-codex) | Hosted reviewed project decisions, work state, evidence, and handoffs | Reviewed evidence rather than raw transcript sharing | Braid is self-hosted, peer-sovereign, cryptographically recipient-bound, revisioned, and conflict preserving | Strong commercial UX benchmark; keep the open protocol/control-plane boundary clear |
| [nodeterm Context Link](https://nodeterm.dev/docs/agents/context-link/) | Visual links and transcript/summary pulling between live agent nodes | Existing-agent context transfer | Braid extracts typed claims, minimizes them, signs the result, and quarantines it; it does not require raw transcript pull | Do not build a terminal UI first; remain usable from any compatible agent application |
| [Mem0](https://docs.mem0.ai/), [Letta shared memory](https://docs.letta.com/guides/core-concepts/memory/shared-memory/), and [LangGraph memory](https://docs.langchain.com/oss/python/langgraph/add-memory) | Memory extraction, storage, retrieval, and shared application state | Persistent agent knowledge | Braid is a boundary transaction between sovereign stores, not the store of record or retrieval engine | Add connectors so a team can keep its chosen memory backend |
| [GitHub Copilot Memory](https://docs.github.com/en/copilot/concepts/agents/copilot-memory) | Repository-scoped facts and preferences with citations | Shared developer knowledge | Braid includes cross-project purpose, exact recipients, revisions, active disagreement, and non-GitHub agents | Complement repository memory with cross-agent handoffs |
| [.apc Agent Project Context](https://agentprojectcontext.com/en/docs/introduction/) | Neutral repository contract for agent behavior | Portable project context | `.apc` is a stable project contract; Braid moves changing, recipient-scoped work state | Export accepted summaries into project context when useful |

## Originality and defensibility

| Capability | Separation today | Honest assessment |
|---|---:|---|
| HTTP relay, mailboxes, and encryption | Low | Necessary plumbing built from standard primitives; not a moat |
| Signed portable memory records | Low-medium | Valuable, but PAM, UMP, MMP, and others make this a crowded protocol area |
| Existing Claude Code to Codex session interoperability | Medium-high | Useful and relatively uncommon, but other cross-runtime tools exist |
| Reviewed semantic revisions instead of transcript transfer | Medium-high | A clear product choice shared by a smaller set of competitors |
| Recipient/purpose/sensitivity minimization plus disclosure audit | High | The combination gives teams a concrete data-loss and accountability control |
| Quarantine plus conflict-preserving merge | High | Most shared-memory products optimize convergence; preserving unresolved disagreement is materially different |
| Signed Context Pull Request and correlated bounded response | High | The surveyed products expose memory, messaging, tasks, or shared brains; this explicit context-review transaction is uncommon |

The moat is therefore not a single schema or cipher. It is the end-to-end
workflow, policy behavior, test corpus, audit evidence, integrations, and team
habit around trustworthy context changes.

## The product-shaped workflow

```text
Alice asks Bob's trusted endpoint
  purpose + question + selectors + since revision + ceilings
                         |
                         v
Bob verifies identity and local scope, then selects only matching active claims
                         |
                         v
Bob signs the response and exact Context Pack digest; Team Hub carries ciphertext
                         |
                         v
Alice verifies correlation and budgets -> quarantine -> review -> accept/reconcile
                         |
                         v
Both ledgers retain provenance, disclosure history, and unresolved disagreement
```

Three concrete uses follow from the same transaction:

1. **Developer catch-up:** "What auth decisions and blockers changed since this
   revision?" returns only changed, reviewed claims instead of a transcript.
2. **Cross-team dependency check:** a project agent asks another team's endpoint
   for public API constraints under a standing low-sensitivity policy.
3. **Incident handoff:** an on-call agent requests confirmed facts, rejected
   hypotheses, and open actions, then reconciles them with its local incident
   ledger without granting the sender command authority.

## Build / integrate / avoid

Build next where it compounds the differentiated layer:

1. **Context CI and signed acceptance receipts.** Prove which requested claims
   were quarantined, accepted, rejected, superseded, or left in disagreement.
2. **Policy-as-code standing requests.** Let teams pre-authorize exact peers,
   purposes, claim kinds, labels, sensitivity, byte budgets, and schedules while
   forcing scope expansion or credential findings to a human.
3. **Protocol bridges.** Carry the same request/response objects as A2A
   artifacts and import/export UMP or PAM records. Compatibility is stronger
   separation than another closed silo.
4. **Team controls.** Add OIDC/SSO mapping, Postgres storage, HA, external audit
   export, retention policy, and key rotation before enterprise claims.
5. **Outcome UX.** Show "what changed for me," why each claim was included,
   what the peer declined, and which conflicts remain unresolved.

Integrate discovery, carrier security, and memory backends. Avoid building a
universal agent directory, general task orchestrator, vector store, terminal
application, chat client, or raw transcript synchronization product.

## Current gaps

- Python-only SDK and CLI; no published language-neutral conformance suite.
- Single-node SQLite Team Hub; no HA, SSO/SCIM, tenant-isolation certification,
  centralized recovery, or compliance attestation.
- No universal discovery. Enrollment and out-of-band principal comparison are
  intentionally explicit.
- No vendor can be awakened after its application or task has ended.
- No standing-policy engine yet; agent skill instructions enforce the ordinary
  in-scope behavior.
- Early project with limited independent adoption and integration evidence.

These gaps make controlled developer-team pilots the honest current market,
not regulated enterprise deployment.
