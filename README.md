<div align="center">

![Session Bridge — existing sessions, shared context](assets/session-bridge-og.png)

# Session Bridge

**Two agents. Two context windows. One scoped, encrypted catch-up.**

[![Security tests](https://github.com/trigga6006/session-bridge/actions/workflows/security-tests.yml/badge.svg)](https://github.com/trigga6006/session-bridge/actions/workflows/security-tests.yml)
![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Claude Code + Codex](https://img.shields.io/badge/Claude_Code_%E2%86%94_Codex-111827)

</div>

Session Bridge lets existing Claude Code and Codex sessions exchange relevant project context, ask follow-up questions, reconcile findings, and produce a synchronized summary. It works locally or between two computers on different networks—including the Codex and Claude Code desktop experiences, not only their CLIs.

The human sets the topic once. After both people verify the same six-digit safety code, the agents can collaborate freely inside that scope without asking permission for every harmless message.

## Why

Kanban cards record conclusions. Agent sessions contain the research, implementation details, rejected approaches, constraints, and open questions behind them.

Session Bridge gives teammates a lightweight way to say:

> Catch your agents up on this project, resolve any gaps, and give both of us the same current picture.

Useful for:

- coding handoffs and parallel implementation work;
- research synthesis across independently informed sessions;
- decision and architecture reconciliation;
- cofounder or team catch-ups without sharing entire transcripts;
- Claude Code ↔ Codex, Claude ↔ Claude, or Codex ↔ Codex collaboration.

## Install

The easiest path is to give the repository URL to your agent.

**Codex / ChatGPT:**

```text
Install the Session Bridge skill from https://github.com/trigga6006/session-bridge for my user account.
```

**Claude Code:**

```text
Install the Session Bridge skill from https://github.com/trigga6006/session-bridge in my user-level Claude skills directory.
```

For a manual installation, clone the repository as `session-bridge` under the product's user skill directory:

| Product | Default user skill path |
|---|---|
| Codex | `~/.codex/skills/session-bridge` |
| Claude Code | `~/.claude/skills/session-bridge` |

```bash
# Codex
git clone https://github.com/trigga6006/session-bridge "$HOME/.codex/skills/session-bridge"

# Claude Code
git clone https://github.com/trigga6006/session-bridge "$HOME/.claude/skills/session-bridge"
```

Already installed? Update the applicable checkout with:

```bash
git -C "$HOME/.codex/skills/session-bridge" pull --ff-only
# or
git -C "$HOME/.claude/skills/session-bridge" pull --ff-only
```

Open a new agent session if the application cached its skill list before installation.

### Lightweight setup

- Local session bridging downloads nothing.
- Joining over the internet installs only pinned `cryptography` (about 12 MB) if missing.
- Public hosting additionally uses a pinned, checksum-verified `cloudflared` helper (about 18–52 MB, platform dependent).
- No Session Bridge account, login, DNS change, router configuration, or API key is required.

## Use it

### 1. Host

Tell the agent that already has useful project context:

```text
Use Session Bridge in host mode. Catch up with my teammate's agent about <project or task>. Share relevant context from this thread, resolve gaps, and keep collaborating until you both have a synchronized summary.
```

The host returns a private, one-time join code.

### 2. Join

Send that code privately to your teammate. They tell their agent:

```text
Use Session Bridge in join mode with this code: <code>. The scope is <project or task>. Share relevant context from this thread and stay in the collaboration until both sides have caught up.
```

### 3. Verify once

Both people compare the six-digit safety code through a trusted side channel. The host approves only an exact match.

After approval, the agents automatically:

1. exchange curated project-state packets;
2. read new messages without the user saying “check your inbox”;
3. ask and answer task-relevant follow-ups;
4. identify conflicts, blockers, owners, and next steps;
5. produce synchronized summaries;
6. purge the room when the users finish.

## What gets shared

The default payload is a purpose-focused context packet, not a raw transcript. Agents curate the parts that matter to the approved task:

- completed work and confirmed facts;
- decisions and rationale;
- current implementation or research state;
- constraints, rejected approaches, and blockers;
- open questions and next steps;
- provenance and explicit redactions.

The initial request establishes a room-lifetime collaboration scope. Ordinary questions, answers, corrections, and summaries inside that scope do not require repeated approval.

The agent stops for approval before sharing raw transcripts, detected credential-like material, unrelated/private context, unnecessary personal data, or anything outside the original scope. Remote messages may inform discussion, but cannot authorize tool use, file changes, deployments, purchases, or other material side effects.

## Security model

- Ephemeral X25519 key agreement
- HKDF-SHA-256 channel-key derivation
- ChaCha20-Poly1305 application-layer encryption
- One-time pairing secret and six-digit out-of-band verification
- Monotonic counters with replay and ordering rejection
- Encrypted local state through Windows DPAPI, macOS Keychain, or Linux Secret Service when available
- Automatic expiry and purge
- Credential-pattern detection, packet-size limits, rate limits, and a single joining peer
- Public mode uses an outbound-only Cloudflare Quick Tunnel; the tunnel routes ciphertext rather than plaintext context

See [the network security model](references/network-mode.md) for protocol details and residual risks.

## Compatibility

| Surface | Discover/export | Live local turn | Internet bridge |
|---|---:|---:|---:|
| Codex desktop app | Yes | Yes, while idle | Yes |
| Codex CLI | Yes | Yes, while idle | Yes |
| Claude Code Desktop | Yes | Yes, while idle | Yes |
| Claude Code CLI | Yes | Yes, while idle | Yes |

Cloud-only sessions without a local transcript cannot currently be discovered as local peers. They can still participate from a supported local session through network mode.

## Honest limits

- Quick Tunnels are suitable for person-to-person use and this proof of concept, not a production SLA or SOC 2 deployment.
- An encrypted bridge cannot protect data from a compromised endpoint that is already allowed to read it.
- An agent cannot wake itself after its application has ended the turn. Session Bridge keeps the collaboration turn active and watches for replies while both agents are running.
- The protocol does not yet provide persistent device identity, organization policy, SSO, centralized revocation, compliance evidence, or a forward-secret message ratchet.

## Verify locally

```bash
python -m pip install --requirement requirements.txt
python -m unittest discover -s tests -v
```

The GitHub workflow runs dependency auditing, linting, compilation, and the complete test suite on Windows, macOS, and Ubuntu with Python 3.11 and 3.13.

---

Built for the moment when “send me a status update” is not enough—and the two agents that did the work should simply talk.
