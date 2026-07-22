# Offline context-quality benchmark

This measures the product boundary that message relays lack: semantic claims, supersession, conflict-safe merge, freshness, recipient policy, provenance, secret containment, and useful compression.

Run `python -m benchmarks.context_quality.runner --engine reference --holdout-seed 20260722 --out benchmark-results`.

An engine receives `context-benchmark/v1` JSON on stdin and emits JSON containing `claims`, `diff`, `merge`, `stale_claim_ids`, `recipient_pack`, and `audit`. The evaluator independently scans full output for sentinel PII/secrets and hard-fails secret/denied disclosure, missing source provenance, unsafe conflict resolution, or a missed stale claim. `raw` and `markdown` are honest transport-only controls and fail these gates.
