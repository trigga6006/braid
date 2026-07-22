"""Repeatable latency/allocation benchmark for the complete signed ledger lifecycle."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import time
import tracemalloc
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from context_model import make_claim  # noqa: E402
from context_store import ContextLedger  # noqa: E402
import network_bridge  # noqa: E402


OBSERVED_AT = "2026-07-22T00:00:00Z"


def claims(count: int) -> list[dict[str, Any]]:
    return [
        make_claim(
            f"claim-benchmark-{index:04d}",
            "fact",
            f"Benchmark fact {index} was verified by the synthetic test suite.",
            f"benchmark-fact-{index:04d}",
            [
                {
                    "type": "test_result",
                    "uri": f"test://lifecycle/{index}",
                    "digest": "sha256:" + f"{index:064x}"[-64:],
                    "observed_at": OBSERVED_AT,
                }
            ],
            confidence="confirmed",
            observed_at=OBSERVED_AT,
        )
        for index in range(count)
    ]


def sample(count: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="braid-lifecycle-") as directory:
        root = Path(directory)
        sender = ContextLedger("benchmark-sender", root / "sender")
        receiver = ContextLedger("benchmark-receiver", root / "receiver")
        payload = claims(count)
        output = root / "disclosure.json"
        tracemalloc.start()
        started = time.perf_counter()
        staged = sender.stage(payload, "benchmark")
        review = sender.review_staged(staged["stage_id"])
        sender.approve_staged(staged["stage_id"], review["review_digest"])
        revision = sender.commit("benchmark")
        sender.export(revision["id"], output, recipient=receiver.principal)
        token = receiver.import_quarantine(output)
        receiver.review_import(token)
        accepted = receiver.accept_import(token)
        elapsed_ms = (time.perf_counter() - started) * 1_000
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        if len(accepted["claims"]) != count:
            raise AssertionError("Accepted claim count does not match benchmark input.")
        if not sender.verify_audit() or not receiver.verify_audit():
            raise AssertionError("Audit verification failed during benchmark.")
        return {
            "elapsed_ms": elapsed_ms,
            "peak_python_bytes": peak,
            "bundle_bytes": output.stat().st_size,
        }


def run(sizes: tuple[int, ...] = (10, 100, 500), iterations: int = 3) -> dict[str, Any]:
    if iterations < 1 or any(size < 1 or size > 500 for size in sizes):
        raise ValueError("Use 1-500 claims and at least one iteration.")
    os.environ.setdefault("SESSION_BRIDGE_DISABLE_KEYCHAIN", "1")
    network_bridge.crypto_imports()
    results: dict[str, Any] = {}
    for size in sizes:
        samples = [sample(size) for _ in range(iterations)]
        results[str(size)] = {
            "iterations": iterations,
            "median_elapsed_ms": statistics.median(
                item["elapsed_ms"] for item in samples
            ),
            "max_peak_python_bytes": max(item["peak_python_bytes"] for item in samples),
            "median_bundle_bytes": statistics.median(
                item["bundle_bytes"] for item in samples
            ),
            "samples": samples,
        }
    return {
        "schema": "session-bridge-lifecycle-benchmark/v1",
        "methodology": {
            "lifecycle": "stage-review-approve-commit-export-quarantine-review-accept",
            "allocation": "Python tracemalloc peak; excludes process RSS and tunnel/network costs",
            "timing": "warm local single-process wall clock",
        },
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "logical_cpus": os.cpu_count(),
        },
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", nargs="+", type=int, default=[10, 100, 500])
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    report = run(tuple(args.sizes), args.iterations)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
