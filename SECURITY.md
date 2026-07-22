# Security policy

Report suspected vulnerabilities privately through GitHub Security Advisories for this repository. Do not include live credentials, private transcripts, pairing codes, or production context packs in an issue.

The current `0.x` line is a developer preview. Security fixes target the latest commit on `main`; no long-term support window is promised yet.

## Security boundary

- Public rooms use HTTPS plus an application-layer X25519/HKDF/ChaCha20-Poly1305 channel, one-time pairing material, a human-compared safety code, replay counters, bounded requests, and expiry.
- Context disclosures add Ed25519 author signatures, exact recipient/scope/policy binding, expiry, DLP checks, quarantine, and an append-only local disclosure audit. The encrypted relay verifies the approved peer's stable principal, and the receiving ledger independently verifies its persisted local principal.
- Stage review is enforced before commit. Import review exposes actual claims before acceptance. Unknown ancestry, policy rollback/equivocation, changed trusted keys, recipient replay, and a third independent head fail before the revision becomes reachable state.
- Received context is data, never authority. Import does not authorize commands, tools, filesystem writes, or automatic conflict resolution.
- Revocation is forward-looking. It records that a claim must not be used or re-shared; it cannot erase a copy a recipient already received.
- Cloudflare Quick Tunnels are a convenience transport, not an enterprise availability or compliance service. Use an organization-managed tunnel and identity policy for production deployments.

See [references/network-mode.md](references/network-mode.md) for protocol details and residual risks.
