"""Run an offline context-engine benchmark; external engines use JSON stdin/stdout."""

from __future__ import annotations
import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Any
from .fixtures import holdout_fixtures, public_fixtures, request_for
from .oracle import aggregate, reference_result, score


def invoke(
    command: str | None, fixture: Any, timeout: float
) -> tuple[dict[str, Any], float]:
    started = time.perf_counter()
    if not command or command == "reference":
        output = reference_result(fixture)
    elif command in ("raw", "markdown"):
        output = {
            "claims": [],
            "diff": [],
            "merge": {"claims": [], "conflicts": []},
            "stale_claim_ids": [],
            "recipient_pack": {
                "text": "\n".join(e["text"] for e in fixture.events),
                "claims": [],
            },
            "audit": [],
        }
    else:
        process = subprocess.run(
            command,
            input=json.dumps(request_for(fixture)),
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if process.returncode:
            raise RuntimeError(
                f"engine failed ({process.returncode}): {process.stderr[-800:]}"
            )
        output = json.loads(process.stdout)
        if not isinstance(output, dict):
            raise ValueError("engine output must be a JSON object")
    return output, (time.perf_counter() - started) * 1000


def markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Context Quality Benchmark",
        "",
        f"Engine: `{report['engine']}`",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    lines += [f"| {key} | {value:.4f} |" for key, value in report["metrics"].items()]
    lines += [
        "",
        f"Hard gates: **{'PASS' if report['hard_gates_passed'] else 'FAIL'}**",
        "",
        "| Fixture | Pass | Claim F1 | Diff F1 | Required recall | Compression |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    lines += [
        "| %s | %s | %.3f | %.3f | %.3f | %.2fx |"
        % (
            r["fixture"],
            "yes" if r["passed"] else "no",
            r["claims"]["f1"],
            r["diff"]["f1"],
            r["required_recall"],
            r["compression_ratio"],
        )
        for r in report["fixtures"]
    ]
    return "\n".join(lines) + "\n"


def run(
    engine: str | None = "reference",
    holdout_seed: int | None = None,
    timeout: float = 10,
) -> dict[str, Any]:
    rows = []
    for fixture in public_fixtures() + (
        holdout_fixtures(holdout_seed) if holdout_seed is not None else []
    ):
        output, elapsed = invoke(engine, fixture, timeout)
        row = score(fixture, output)
        row["elapsed_ms"] = elapsed
        rows.append(row)
    report = aggregate(rows)
    report["engine"] = engine or "reference"
    report["holdout_seed"] = holdout_seed
    report["p95_ms"] = sorted(r["elapsed_ms"] for r in rows)[
        max(0, int(len(rows) * 0.95) - 1)
    ]
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", default="reference")
    parser.add_argument("--holdout-seed", type=int)
    parser.add_argument("--out", type=Path, default=Path("benchmark-results"))
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    report = run(args.engine, args.holdout_seed, args.timeout)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "context-quality.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    (args.out / "context-quality.md").write_text(markdown(report), encoding="utf-8")
    print(
        json.dumps(
            {
                "hard_gates_passed": report["hard_gates_passed"],
                "p95_ms": report["p95_ms"],
            }
        )
    )
    return 0 if report["hard_gates_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
