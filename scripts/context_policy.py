"""Fail-closed recipient planning for Context Pack disclosures.

The planner is deterministic and intentionally conservative. It selects only
active, non-revoked claims that fit the recipient's declared clearance,
audience, purpose, and size budget. It returns reasons for every inclusion and
exclusion so an agent or human can review the proposed disclosure before send.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Iterable, Mapping

from context_model import canonical_json, resolved_active_view, validate_claim
from context_security import scan_sensitive


SENSITIVITY_RANK = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
DEFAULT_PRIORITY = {
    "blocker": 100,
    "constraint": 95,
    "decision": 90,
    "disagreement": 85,
    "action": 80,
    "question": 75,
    "fact": 60,
    "hypothesis": 45,
}
WORD = re.compile(r"[a-z0-9][a-z0-9_.:/-]{1,}", re.IGNORECASE)


class PolicyError(ValueError):
    """A disclosure request is invalid or violates recipient policy."""


def _words(value: str) -> set[str]:
    return {word.casefold() for word in WORD.findall(value)}


def _profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    principal = profile.get("principal_id")
    if not isinstance(principal, str) or not principal.strip() or len(principal) > 256:
        raise PolicyError("recipient principal_id is required")
    clearance = profile.get("max_sensitivity", "internal")
    if clearance not in SENSITIVITY_RANK:
        raise PolicyError("recipient max_sensitivity is unsupported")
    max_claims = profile.get("max_claims", 100)
    max_bytes = profile.get("max_bytes", 200_000)
    if (
        isinstance(max_claims, bool)
        or not isinstance(max_claims, int)
        or not 1 <= max_claims <= 500
    ):
        raise PolicyError("recipient max_claims must be between 1 and 500")
    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or not 1_024 <= max_bytes <= 1_000_000
    ):
        raise PolicyError("recipient max_bytes must be between 1024 and 1000000")
    audiences = profile.get("audiences", [])
    if not isinstance(audiences, list) or not all(
        isinstance(item, str) and item for item in audiences
    ):
        raise PolicyError("recipient audiences must be strings")
    return {
        "principal_id": principal.strip(),
        "max_sensitivity": clearance,
        "max_claims": max_claims,
        "max_bytes": max_bytes,
        "audiences": sorted(set(audiences)),
        "purpose": str(profile.get("purpose", "")).strip(),
    }


def plan_disclosure(
    revisions: Iterable[Mapping[str, Any]],
    recipient_profile: Mapping[str, Any],
    *,
    revoked_claim_ids: Iterable[str] = (),
    required_claim_ids: Iterable[str] = (),
    now: str | None = None,
) -> dict[str, Any]:
    """Return a reviewable, minimized disclosure plan; never transmit data."""
    profile = _profile(recipient_profile)
    revoked, required = set(revoked_claim_ids), set(required_claim_ids)
    active = resolved_active_view(revisions, now)["active_claims"]
    query = _words(profile["purpose"])
    allowed_audiences = set(profile["audiences"]) | {profile["principal_id"]}
    candidates: list[tuple[int, dict[str, Any], list[str]]] = []
    excluded: list[dict[str, Any]] = []
    known_ids = {claim["id"] for claim in active}
    missing = sorted(required - known_ids)
    if missing:
        raise PolicyError("required claim is not active: " + missing[0])
    for original in active:
        validate_claim(original)
        claim = copy.deepcopy(original)
        reasons: list[str] = []
        sensitivity = claim.get("sensitivity", "internal")
        if claim["id"] in revoked:
            excluded.append({"claim_id": claim["id"], "reason": "revoked"})
            continue
        if SENSITIVITY_RANK[sensitivity] > SENSITIVITY_RANK[profile["max_sensitivity"]]:
            excluded.append(
                {
                    "claim_id": claim["id"],
                    "reason": "sensitivity exceeds recipient clearance",
                }
            )
            continue
        audience = set(claim.get("audience", []))
        if audience and not audience.intersection(allowed_audiences):
            excluded.append(
                {
                    "claim_id": claim["id"],
                    "reason": "recipient is outside claim audience",
                }
            )
            continue
        if scan_sensitive(claim):
            excluded.append(
                {
                    "claim_id": claim["id"],
                    "reason": "secret scanner finding requires explicit redaction",
                }
            )
            continue
        score = DEFAULT_PRIORITY.get(claim["kind"], 0)
        overlap = query.intersection(
            _words(claim["statement"] + " " + " ".join(claim.get("labels", [])))
        )
        if overlap:
            score += 20 + min(20, len(overlap) * 4)
            reasons.append("matches disclosure purpose")
        if claim["id"] in required:
            score += 10_000
            reasons.append("explicitly required")
        if claim["confidence"] == "confirmed":
            score += 5
            reasons.append("confirmed evidence")
        reasons.append(f"{claim['kind']} priority")
        candidates.append((score, claim, reasons))
    candidates.sort(key=lambda item: (-item[0], item[1]["id"]))
    selected: list[dict[str, Any]] = []
    inclusions: list[dict[str, Any]] = []
    used = 2
    for score, claim, reasons in candidates:
        claim_bytes = len(canonical_json(claim)) + (1 if selected else 0)
        if (
            len(selected) >= profile["max_claims"]
            or used + claim_bytes > profile["max_bytes"]
        ):
            if claim["id"] in required:
                raise PolicyError("required claims exceed recipient disclosure budget")
            excluded.append(
                {"claim_id": claim["id"], "reason": "recipient disclosure budget"}
            )
            continue
        selected.append(claim)
        used += claim_bytes
        inclusions.append({"claim_id": claim["id"], "score": score, "reasons": reasons})
    selected_ids = {claim["id"] for claim in selected}
    if not required <= selected_ids:
        raise PolicyError("a required claim could not be disclosed")
    return {
        "recipient": profile["principal_id"],
        "purpose": profile["purpose"],
        "claims": selected,
        "included": inclusions,
        "excluded": sorted(excluded, key=lambda item: item["claim_id"]),
        "budget": {
            "max_claims": profile["max_claims"],
            "max_bytes": profile["max_bytes"],
            "used_bytes": used,
        },
        "requires_review": True,
    }
