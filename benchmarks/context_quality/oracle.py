"""Independent validator and scorer; it never trusts engine-reported metrics."""

from __future__ import annotations

from copy import deepcopy
from typing import Any
import json

from .fixtures import Fixture


def canonical_claim(claim: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        json.dumps(
            claim.get(key), sort_keys=True, ensure_ascii=False, separators=(",", ":")
        )
        for key in ("id", "kind", "subject", "predicate", "value", "status", "scope")
    )


def ids(value: Any) -> set[str]:
    return (
        {
            str(item.get("id"))
            for item in value
            if isinstance(item, dict) and item.get("id")
        }
        if isinstance(value, list)
        else set()
    )


def reference_result(fixture: Fixture) -> dict[str, Any]:
    claims = deepcopy(fixture.claims)
    for claim in claims:
        if claim["id"] in fixture.denied:
            claim["value"], claim["redactions"] = "[REDACTED]", ["recipient-policy"]
    allowed = [
        c
        for c in claims
        if c["id"] not in fixture.denied and c["id"] not in fixture.stale
    ]
    return {
        "claims": claims,
        "diff": deepcopy(fixture.diff),
        "merge": {
            "claims": claims,
            "conflicts": [
                {"key": c, "resolution": "manual"} for c in fixture.conflicts
            ],
        },
        "stale_claim_ids": fixture.stale,
        "recipient_pack": {"claims": allowed, "claim_ids": [c["id"] for c in allowed]},
        "audit": [
            {"claim_id": c, "decision": "deny", "reason": "recipient policy"}
            for c in fixture.denied
        ],
    }


def _prf(actual: set[Any], expected: set[Any]) -> dict[str, float]:
    tp, fp, fn = len(actual & expected), len(actual - expected), len(expected - actual)
    p = tp / (tp + fp) if tp + fp else (1.0 if not expected else 0.0)
    r = tp / (tp + fn) if tp + fn else 1.0
    return {"precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0.0}


def score(fixture: Fixture, output: dict[str, Any]) -> dict[str, Any]:
    claims = output.get("claims", []) if isinstance(output.get("claims"), list) else []
    expected = deepcopy(fixture.claims)
    for claim in expected:
        if claim["id"] in fixture.denied:
            claim["value"] = "[REDACTED]"
    claim_score = _prf(
        {canonical_claim(c) for c in claims if isinstance(c, dict)},
        {canonical_claim(c) for c in expected},
    )
    event_ids = {e["id"] for e in fixture.events}
    expected_sources = {
        str(c["id"]): {str(s["event_id"]) for s in c["sources"]} for c in fixture.claims
    }
    invalid_provenance = []
    for claim in claims:
        sources = claim.get("sources", []) if isinstance(claim, dict) else []
        actual = {str(s.get("event_id")) for s in sources if isinstance(s, dict)}
        if (
            not sources
            or any(
                not isinstance(s, dict) or s.get("event_id") not in event_ids
                for s in sources
            )
            or actual != expected_sources.get(str(claim.get("id")), set())
        ):
            invalid_provenance.append(str(claim.get("id", "<unknown>")))
    actual_diff = {
        f"{x.get('op')}:{x.get('before', '')}:{x.get('after', '')}"
        for x in output.get("diff", [])
        if isinstance(x, dict)
    }
    expected_diff = {
        f"{x['op']}:{x.get('before', '')}:{x.get('after', '')}" for x in fixture.diff
    }
    diff_score = _prf(actual_diff, expected_diff)
    stale_score = _prf(
        {str(x) for x in output.get("stale_claim_ids", [])}, set(fixture.stale)
    )
    merge = output.get("merge", {}) if isinstance(output.get("merge"), dict) else {}
    conflict_score = _prf(
        {str(c.get("key")) for c in merge.get("conflicts", []) if isinstance(c, dict)},
        set(fixture.conflicts),
    )
    unsafe = [
        c
        for c in merge.get("conflicts", [])
        if isinstance(c, dict)
        and c.get("resolution") not in ("manual", "defer", "proven-by-evidence")
    ]
    missing_competitor = sorted(
        ({c["id"] for c in fixture.claims} - ids(merge.get("claims", [])))
        if fixture.conflicts
        else set()
    )
    pack = (
        output.get("recipient_pack", {})
        if isinstance(output.get("recipient_pack"), dict)
        else {}
    )
    pack_ids = ids(pack.get("claims", [])) | {str(x) for x in pack.get("claim_ids", [])}
    serialized = json.dumps(output, sort_keys=True, ensure_ascii=False)
    leaks = sorted(
        value
        for value in fixture.secret_values
        if value.casefold() in serialized.casefold()
    )
    denied_release = sorted(pack_ids & set(fixture.denied))
    missing_required = sorted(set(fixture.required) - pack_ids)
    audit_ids = {
        str(x.get("claim_id"))
        for x in output.get("audit", [])
        if isinstance(x, dict) and x.get("decision") == "deny"
    }
    audit_missing = sorted(set(fixture.denied) - audit_ids)
    raw_bytes, pack_bytes = (
        len(json.dumps(fixture.events, separators=(",", ":")).encode()),
        len(json.dumps(pack, separators=(",", ":")).encode()),
    )
    gates = {
        "privacy": not leaks and not denied_release and not audit_missing,
        "provenance": not invalid_provenance,
        "conflicts": not unsafe
        and not missing_competitor
        and (not fixture.conflicts or conflict_score["recall"] == 1.0),
        "freshness": not set(fixture.stale) or stale_score["recall"] == 1.0,
    }
    return {
        "fixture": fixture.name,
        "claims": claim_score,
        "diff": diff_score,
        "stale": stale_score,
        "conflicts": conflict_score,
        "required_recall": 1 - len(missing_required) / len(fixture.required)
        if fixture.required
        else 1.0,
        "compression_ratio": raw_bytes / max(pack_bytes, 1),
        "raw_bytes": raw_bytes,
        "pack_bytes": pack_bytes,
        "leaks": leaks,
        "denied_release": denied_release,
        "audit_missing": audit_missing,
        "invalid_provenance": invalid_provenance,
        "unsafe_conflicts": unsafe,
        "missing_competitor": missing_competitor,
        "gates": gates,
        "passed": all(gates.values()),
    }


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = {
        f"{key}_{part}": sum(row[key][part] for row in rows) / len(rows)
        for key in ("claims", "diff", "stale", "conflicts")
        for part in ("precision", "recall", "f1")
    }
    metrics["required_recall"] = sum(r["required_recall"] for r in rows) / len(rows)
    metrics["compression_ratio"] = sum(r["compression_ratio"] for r in rows) / len(rows)
    return {
        "metrics": metrics,
        "hard_gates_passed": all(r["passed"] for r in rows),
        "fixtures": rows,
    }
