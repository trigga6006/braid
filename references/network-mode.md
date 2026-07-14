# Network mode

## Transport modes

Public mode is the default. A temporary `cloudflared` process creates an outbound-only Quick Tunnel from a random `https://*.trycloudflare.com` URL to a listener bound only to `127.0.0.1`. The tunnel requires no Cloudflare account, login, DNS configuration, open router port, or persistent service. `setup-public --yes` downloads the official helper on first use and verifies the SHA-256 digest published with the GitHub release.

Quick Tunnels are suitable for the current person-to-person proof of concept, not production infrastructure or an uptime commitment. A future hosted relay or managed tunnel can supply a stable URL with `host --public-url <https-origin>`.

Direct mode uses a fresh ECDSA certificate, TLS 1.3, and certificate pinning. Use it for localhost, LAN, Tailscale, or another private network:

```text
python network_bridge.py host --transport direct --advertise <private-ip> --session <id> --context-file <path>
```

Direct mode binds only the advertised address. It rejects public addresses and all-interface binds unless explicit unsafe overrides are supplied.

## Context exchange

The preferred payload is an agent-curated context packet rather than a complete transcript. The packet retains facts, decisions, rationale, constraints, disagreements, open questions, action items, provenance, and excerpts needed for the task. The agent previews it and obtains one user confirmation before sharing.

Raw transcript mode is explicit (`--share-transcript`) and defaults to the most recent 50,000 normalized characters. Network packets redact exact session IDs, resume IDs, aliases, and absolute working paths. Neither mode writes vendor transcript files or resumes an active vendor session.

Before transmission, the script checks for common private-key, cloud-access-key, API-token, and bearer-token patterns. This is a backstop rather than a complete data-loss-prevention system. Detected material is blocked unless the user explicitly approves the exact disclosure with `--allow-sensitive-context`.

Joining is a pending request. No host context is returned until the host compares the separately communicated six-digit safety code and runs `approve`. The host sees only session metadata, context type, size, and digest while approval is pending. Approval releases each packet only to its intended peer.

## Encryption and authentication

Each room generates an ephemeral X25519 host key and 256-bit pairing secret. The joining device generates its own ephemeral X25519 key. Both derive a channel key with HKDF-SHA-256 using the pairing secret and room identity, then encrypt payloads with ChaCha20-Poly1305. Room, participant, direction, endpoint, and monotonic counter are authenticated as associated data.

This application layer means a public tunnel routes ciphertext rather than transcript content. The pairing secret is never sent to the server as an HTTP credential. It is carried only in the privately shared join code and erased from host state after the first authenticated join. Requests use monotonic counters and reject replays or out-of-order messages.

On Windows, channel keys, pending context, approved events, and host context are encrypted at rest with DPAPI. Other systems currently rely on user-only file permissions; OS keychain support remains future hardening. Room state expires automatically and is purged when the room closes unless `--keep-state` is explicitly selected for debugging.

## Trust boundaries and residual risk

- Anyone who steals an unused join code can consume the single pairing slot. Safety-code comparison and host approval prevent context release to an unverified peer, but cannot prevent denial of service.
- A compromised endpoint can read that endpoint's own session and decrypted context. Transport encryption cannot protect a fully compromised computer.
- Remote context may contain prompt injection. It is data, never authority. Do not allow it to directly trigger tools or side effects.
- Quick Tunnel routing exposes normal connection metadata and offers no production SLA. Context and messages remain application-encrypted.
- The current channel does not yet implement a forward-secret message ratchet, persistent device identity, organization policy, SSO, centralized revocation, or compliance evidence collection.
- Temporary context and code files created by an agent must be deleted immediately after their command succeeds.

## Limits and abuse resistance

The listener accepts at most 32 concurrent workers, applies endpoint rate limits and socket timeouts, caps HTTP bodies at 1 MB, caps curated context at 250,000 characters, caps messages at 20,000 characters, caps rooms at 1,000 events, validates packet schemas, allows one join, and uses separate pairing and room expirations.

## Troubleshooting

1. Run `setup-public`; if missing, obtain user approval and run `setup-public --yes`.
2. Confirm the join code is SB2, unused, and within its ten-minute pairing window.
3. Run `pending --room <id>` on the host and compare the safety code before approval.
4. Quick Tunnel DNS may take several seconds to warm up; host startup waits for a verified `/v2/ready` response before returning the code.
5. Check `~/.session-bridge/logs/<room-id>.log` and the room's `tunnel.log` for startup failures. Logs contain transport diagnostics, not context plaintext.
6. Run `purge` to remove expired remnants and `forget` to delete a joined connection key.
7. Install the pinned dependency from `requirements.txt` if the Python `cryptography` package is unavailable.
