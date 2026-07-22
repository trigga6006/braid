"""Deterministic benchmark of the real Session Bridge context implementation."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import statistics
import sys
import tempfile
import time
import tracemalloc

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import session_bridge  # noqa: E402
from context_extract import extract_message_claims  # noqa: E402
from context_model import canonical_json, create_revision, make_claim, plan_merge  # noqa: E402
from context_policy import plan_disclosure  # noqa: E402
from context_store import ContextLedger  # noqa: E402


ANCHORS = (
    "Decision: cache TTL is 300 seconds.",
    "Constraint: cache must be invalidated after account deletion.",
    "Blocker: migration fails until the index is deployed.",
    "Open question: should the Redis cluster use three nodes?",
)


def _messages(noise: int) -> list[session_bridge.Message]:
    chatter = ("Thanks!", "Sounds good.", "Acknowledged.", "OK", "Great.")
    values = [
        session_bridge.Message(
            "user", chatter[index % len(chatter)], "2026-07-22T00:00:00Z"
        )
        for index in range(noise)
    ]
    for index, statement in enumerate(ANCHORS):
        values.insert(
            (index + 1) * max(1, len(values) // 5),
            session_bridge.Message(
                "assistant", statement, f"2026-07-22T00:0{index}:00Z"
            ),
        )
    return values


def _revision(claims: list[dict]) -> dict:
    return create_revision(
        "benchmark",
        "revision",
        1,
        [],
        claims,
        [{"principal_id": "benchmark", "display_name": "Benchmark", "role": "owner"}],
        {
            "owner_principal_id": "benchmark",
            "visibility": "scoped",
            "share_policy": "owner_approval",
            "recipients": ["engineering"],
        },
        "benchmark",
        created_at="2026-07-22T00:00:00Z",
    )


def _conflict_gate() -> bool:
    provenance = [
        {
            "type": "test_result",
            "uri": "benchmark:conflict",
            "digest": "sha256:" + "a" * 64,
            "observed_at": "2026-07-22T00:00:00Z",
        }
    ]
    left = make_claim(
        "left",
        "decision",
        "Deploy in us-west-2.",
        "deployment-region",
        provenance,
        observed_at="2026-07-22T00:00:00Z",
    )
    right = make_claim(
        "right",
        "decision",
        "Deploy in eu-west-1.",
        "deployment-region",
        provenance,
        observed_at="2026-07-22T00:00:00Z",
    )
    authors = [
        {"principal_id": "benchmark", "display_name": "Benchmark", "role": "owner"}
    ]
    governance = {
        "owner_principal_id": "benchmark",
        "visibility": "scoped",
        "share_policy": "owner_approval",
        "recipients": ["engineering"],
    }
    first = create_revision(
        "benchmark",
        "left-revision",
        1,
        [],
        [left],
        authors,
        governance,
        "left",
        created_at="2026-07-22T00:00:00Z",
    )
    second = create_revision(
        "benchmark",
        "right-revision",
        1,
        [],
        [right],
        authors,
        governance,
        "right",
        created_at="2026-07-22T00:00:00Z",
    )
    plan = plan_merge([first], [second], "2026-07-22T01:00:00Z")
    return (
        not plan["mergeable"]
        and len(plan["conflicts"]) == 1
        and len(plan["conflicts"][0]["local_claims"]) == 1
        and len(plan["conflicts"][0]["remote_claims"]) == 1
    )


def _signed_round_trip(claims: list[dict]) -> bool:
    previous = os.environ.get("SESSION_BRIDGE_DISABLE_KEYCHAIN")
    os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = "1"
    try:
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            sender = ContextLedger("benchmark-sender", root)
            staged = sender.stage(claims, "benchmark")
            review = sender.review_staged(staged["stage_id"])
            sender.approve_staged(staged["stage_id"], review["review_digest"])
            committed = sender.commit("benchmark")
            bundle = root / "bundle.json"
            receiver = ContextLedger("benchmark-receiver", root)
            sender.export(
                committed["id"],
                bundle,
                receiver.principal,
                [claim["id"] for claim in claims],
            )
            token = receiver.import_quarantine(bundle)
            if receiver.log():
                return False
            receiver.review_import(token)
            accepted = receiver.accept_import(token)
            return len(accepted["claims"]) == len(claims) and receiver.verify_audit()
    finally:
        if previous is None:
            os.environ.pop("SESSION_BRIDGE_DISABLE_KEYCHAIN", None)
        else:
            os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = previous


def run(sizes: tuple[int, ...] = (100, 1_000, 5_000)) -> dict:
    rows = []
    for size in sizes:
        messages = _messages(size)
        raw_bytes = len(
            canonical_json(
                [
                    {"role": m.role, "text": m.text, "timestamp": m.timestamp}
                    for m in messages
                ]
            )
        )
        tracemalloc.start()
        started = time.perf_counter()
        claims = extract_message_claims(messages)
        elapsed_ms = (time.perf_counter() - started) * 1_000
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        statements = {claim["statement"] for claim in claims}
        anchor_recall = len(statements.intersection(ANCHORS)) / len(ANCHORS)
        noise_claims = len(claims) - len(statements.intersection(ANCHORS))
        revision = _revision(claims)
        plan = plan_disclosure(
            [revision],
            {
                "principal_id": "engineering",
                "purpose": "cache migration release Redis",
                "max_sensitivity": "internal",
                "max_claims": 20,
                "max_bytes": 200000,
            },
            required_claim_ids=[claim["id"] for claim in claims],
        )
        pack_bytes = len(canonical_json(plan["claims"]))
        rows.append(
            {
                "messages": len(messages),
                "claims": len(claims),
                "anchor_recall": anchor_recall,
                "noise_claims": noise_claims,
                "compression_ratio": raw_bytes / max(1, pack_bytes),
                "elapsed_ms": elapsed_ms,
                "peak_mib": peak / (1024 * 1024),
            }
        )
    representative = extract_message_claims(_messages(100))
    gates = {
        "required_context_recall": all(row["anchor_recall"] == 1.0 for row in rows),
        "low_signal_suppression": all(row["noise_claims"] == 0 for row in rows),
        # Canonical provenance has fixed overhead on tiny samples. The largest
        # corpus must still demonstrate useful compression over raw chat.
        "compression": rows[-1]["compression_ratio"] > 2.0,
        "conflict_preservation": _conflict_gate(),
        "signed_quarantine_round_trip": _signed_round_trip(representative),
        "bounded_peak_memory": rows[-1]["peak_mib"] < 128,
    }
    latencies = [row["elapsed_ms"] for row in rows]
    return {
        "benchmark": "session-bridge-product/v1",
        "implementation": "real",
        "gates": gates,
        "hard_gates_passed": all(gates.values()),
        "rows": rows,
        "metrics": {
            "median_ms": statistics.median(latencies),
            "max_ms": max(latencies),
            "max_peak_mib": max(row["peak_mib"] for row in rows),
        },
    }


def markdown(report: dict) -> str:
    lines = [
        "# Session Bridge product benchmark",
        "",
        f"Hard gates: **{'PASS' if report['hard_gates_passed'] else 'FAIL'}**",
        "",
        "| Messages | Claims | Anchor recall | Noise claims | Compression | Time (ms) | Peak MiB |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in report["rows"]:
        lines.append(
            f"| {row['messages']} | {row['claims']} | {row['anchor_recall']:.3f} | {row['noise_claims']} | {row['compression_ratio']:.2f}x | {row['elapsed_ms']:.2f} | {row['peak_mib']:.2f} |"
        )
    lines.extend(
        ["", "## Gates", ""]
        + [
            f"- {'PASS' if passed else 'FAIL'}: `{name}`"
            for name, passed in report["gates"].items()
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path("benchmark-results"))
    args = parser.parse_args()
    report = run()
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "product.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.out / "product.md").write_text(markdown(report), encoding="utf-8")
    print(
        json.dumps(
            {"hard_gates_passed": report["hard_gates_passed"], **report["metrics"]}
        )
    )
    return 0 if report["hard_gates_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
