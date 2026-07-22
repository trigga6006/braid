# Session Bridge 0.3.0 benchmark baseline

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
