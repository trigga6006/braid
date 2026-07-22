# Session Bridge benchmark baselines

## 0.3.0 Context Ledger baseline

Measured 2026-07-22 on Windows 11 build 26200, CPython 3.13.3, 24 logical CPUs. These are warm, local, single-process measurements. Python allocation uses `tracemalloc`; it is not process RSS and excludes tunnel/TLS latency, keychain overhead, disk contention, and concurrent workloads.

## Extraction/product gates

Command: `python -m benchmarks.product_benchmark --out benchmark-results/final-product`

| Messages | Extraction | Peak Python allocation | Required-anchor recall | Noise claims | Compression |
|---:|---:|---:|---:|---:|---:|
| 104 | 4.55 ms | 0.018 MiB | 100% | 0 | 2.92x |
| 1,004 | 15.33 ms | 0.010 MiB | 100% | 0 | 27.46x |
| 5,004 | 75.16 ms | 0.009 MiB | 100% | 0 | 136.33x |

All product gates passed: required-context recall, low-signal suppression, compression, bounded extraction allocation, conflict preservation, and a signed quarantine round trip.

## Complete signed lifecycle

Command: `python -m benchmarks.lifecycle_benchmark --iterations 3 --out benchmark-results/final-lifecycle.json`

The measured lifecycle is stage, review, digest approval, commit, recipient-bound export, quarantine import, review, and acceptance. Values are medians except peak allocation, which is the maximum of three samples.

| Claims | Median lifecycle | Max peak Python allocation | Signed bundle |
|---:|---:|---:|---:|
| 10 | 231.53 ms | 2.02 MiB | 8,494 B |
| 100 | 580.28 ms | 2.33 MiB | 61,054 B |
| 500 | 2,511.86 ms | 6.67 MiB | 295,454 B |

The 500-claim row exercises the product's hard claim ceiling and completes with valid sender and receiver audit chains.

## Context-quality contract

`python -m benchmarks.context_quality.runner --engine reference --holdout-seed 20260722 --out benchmark-results/final-context-contract` passed all 18 fixtures and hard gates. The reference engine is a deterministic contract oracle, not a score for automatic extraction quality.

## 0.4.0 Team Hub baseline

Measured on the same host with `python -m benchmarks.team_hub_benchmark --messages 250 --workers 16 --payload-bytes 4096 --out benchmark-results/team-hub-0.4.0.json`.

The transactional SQLite Hub durably accepted all 250 unique opaque envelopes from 16 concurrent workers in 1.421 seconds (175.98 messages/second), paged all 250 in 29.66 ms, and acknowledged them in 22.81 ms. The audit chain verified after acknowledgement and the database plus WAL occupied 2,371,584 bytes. This is a single-host engineering baseline, not an availability or capacity SLA; reverse-proxy latency, network loss, container overhead, and multi-host contention are excluded.
