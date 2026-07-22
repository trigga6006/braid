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
- Team Hub is a blind single-node mailbox: endpoints encrypt each payload to a recipient X25519 key and authenticate requests with Ed25519. The Hub still learns team/project membership, endpoint labels and public keys, sender/recipient routing, timing, sizes, retention state, and network metadata. Use HTTPS on every non-loopback path; application encryption does not hide metadata.
- Team Hub enrollment codes are bearer secrets until redeemed. Transfer each code privately, delete the temporary file after enrollment, and disable a lost endpoint immediately. Every mailbox key is signed by its endpoint identity. Senders additionally pin the exact peer principal, signed binding, and project role after an out-of-band comparison; new or changed directory entries cannot receive automated disclosures until re-approved. Endpoint revocation stops future authenticated access but cannot erase plaintext already decrypted by that endpoint.
- The default Compose stack publishes only to host loopback and expects an HTTPS reverse proxy or managed private ingress on a VPS. Do not expose its internal HTTP port directly. Back up the complete stopped `/data` volume because it contains the database and pinned server identity, and protect that backup as sensitive operational data.
- Team Hub `0.4.x` is single-node SQLite without HA, SSO/SCIM, centralized key recovery, tenant-isolation certification, immutable external audit export, or a compliance attestation. Those are explicit requirements before an enterprise control-plane claim.

See [references/network-mode.md](references/network-mode.md) for temporary-room details and [references/team-hub.md](references/team-hub.md) for Team Hub operations, protocol boundaries, and residual risks.
