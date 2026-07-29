"""Standing authorization for answering Context Pull Requests unattended.

The connector can already answer a request without a human; what it could not
do was decide *whether* answering is in scope. This module is that decision,
and only that decision: it takes an inbound request, a declared policy, the
disclosure plan the responder would send, and the ledger's state, and returns
either an auto-answer authorization or a referral to a human, with reasons.

It transmits nothing, signs nothing, and mutates nothing.

Two rules shape the design.

First, it is fail-closed. Every gate must affirmatively pass; anything unknown,
unparsable, absent, or merely unexpected refers. A policy that cannot be
validated disables automation rather than widening it.

Second, some conditions are never delegable, regardless of what a policy says.
`references/team-hub.md` fixes that list: credential findings, raw transcripts,
unrelated context, restricted sensitivity, scope expansion, and semantic
conflict always stop for review. Those are hard stops here, checked before the
policy is even consulted, and no configuration can switch them off.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any, Iterable, Mapping

from context_model import CLAIM_KINDS, SENSITIVITY
from context_policy import SENSITIVITY_RANK


POLICY_VERSION = 1

# A standing authorization may never cover restricted material, even when the
# operator writes a policy that asks for it.  The ceiling is a property of the
# product boundary, not of the deployment.
AUTO_MAX_SENSITIVITY = "confidential"

# Provenance that means "this claim quotes a vendor session transcript".
# Disclosing raw transcript text is always a human decision.
TRANSCRIPT_PROVENANCE = frozenset({"transcript_excerpt"})

# Exclusion reasons emitted by context_policy.plan_disclosure that indicate the
# secret scanner fired.  The planner already drops these claims, so nothing
# leaks either way -- but a credential finding anywhere in scope is a signal to
# involve a human rather than quietly answer with the remainder.
SECRET_EXCLUSION_MARKER = "secret scanner"

WORD = re.compile(r"[a-z0-9][a-z0-9_.:/-]{1,}", re.IGNORECASE)

_ALLOWED_POLICY_KEYS = frozenset(
    {
        "enabled",
        "version",
        "max_sensitivity",
        "allowed_peers",
        "allowed_kinds",
        "denied_labels",
        "max_claims",
        "max_bytes",
        "max_responses_per_hour",
    }
)

DEFAULT_POLICY: dict[str, Any] = {
    "enabled": False,
    "version": POLICY_VERSION,
    "max_sensitivity": "internal",
    "allowed_peers": [],
    "allowed_kinds": ["decision", "blocker", "constraint", "action"],
    "denied_labels": ["untrusted-source"],
    "max_claims": 25,
    "max_bytes": 50_000,
    "max_responses_per_hour": 12,
}


class AutoPolicyError(ValueError):
    """A standing-authorization policy is malformed."""


def _words(value: str) -> set[str]:
    return {word.casefold() for word in WORD.findall(value)}


def _bounded_int(value: Any, label: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AutoPolicyError(f"{label} must be an integer")
    if not low <= value <= high:
        raise AutoPolicyError(f"{label} must be between {low} and {high}")
    return value


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise AutoPolicyError(f"{label} must be a list of non-empty strings")
    return sorted({item.strip() for item in value})


def load_policy(raw: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate a stored policy, refusing anything it cannot fully understand.

    An unknown key is an error rather than a no-op: silently ignoring a
    misspelled `max_sensitivty` would widen automation beyond what the operator
    believed they authorized.
    """
    if raw is None:
        return dict(DEFAULT_POLICY)
    if not isinstance(raw, Mapping):
        raise AutoPolicyError("auto-respond policy must be a JSON object")
    unknown = set(raw) - _ALLOWED_POLICY_KEYS
    if unknown:
        raise AutoPolicyError(
            "unsupported auto-respond policy field(s): " + ", ".join(sorted(unknown))
        )
    version = raw.get("version", POLICY_VERSION)
    # `type(...) is int` rather than isinstance/equality: `True == 1` and
    # `1.0 == 1`, so a bool or float would otherwise pass as version 1.
    if type(version) is not int or version != POLICY_VERSION:
        raise AutoPolicyError(
            f"auto-respond policy version {version!r} is not supported "
            f"(expected {POLICY_VERSION})"
        )
    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise AutoPolicyError("auto-respond enabled must be true or false")
    sensitivity = raw.get("max_sensitivity", DEFAULT_POLICY["max_sensitivity"])
    if sensitivity not in SENSITIVITY:
        raise AutoPolicyError("auto-respond max_sensitivity is unsupported")
    if SENSITIVITY_RANK[sensitivity] > SENSITIVITY_RANK[AUTO_MAX_SENSITIVITY]:
        raise AutoPolicyError(
            "auto-respond max_sensitivity may not exceed "
            f"{AUTO_MAX_SENSITIVITY}; restricted context always requires review"
        )
    kinds = _string_list(
        raw.get("allowed_kinds", DEFAULT_POLICY["allowed_kinds"]), "allowed_kinds"
    )
    unsupported = sorted(set(kinds) - set(CLAIM_KINDS))
    if unsupported:
        raise AutoPolicyError(
            "auto-respond allowed_kinds contains unknown kind(s): "
            + ", ".join(unsupported)
        )
    peers = _string_list(
        raw.get("allowed_peers", DEFAULT_POLICY["allowed_peers"]), "allowed_peers"
    )
    if enabled and not peers:
        # An empty list must not quietly mean "every peer we have ever
        # trusted", which would extend standing authority to endpoints trusted
        # later for ordinary exchange.  Transport trust is not disclosure
        # authorization.
        raise AutoPolicyError(
            "auto-respond requires an explicit allowed_peers list; "
            "transport trust alone does not authorize unattended answers"
        )
    if enabled and not kinds:
        raise AutoPolicyError(
            "auto-respond requires at least one allowed kind; an empty list "
            "authorizes nothing"
        )
    return {
        "enabled": enabled,
        "version": POLICY_VERSION,
        "max_sensitivity": sensitivity,
        "allowed_peers": peers,
        "allowed_kinds": kinds,
        "denied_labels": _string_list(
            raw.get("denied_labels", DEFAULT_POLICY["denied_labels"]), "denied_labels"
        ),
        "max_claims": _bounded_int(
            raw.get("max_claims", DEFAULT_POLICY["max_claims"]), "max_claims", 1, 200
        ),
        "max_bytes": _bounded_int(
            raw.get("max_bytes", DEFAULT_POLICY["max_bytes"]),
            "max_bytes",
            1_024,
            500_000,
        ),
        "max_responses_per_hour": _bounded_int(
            raw.get("max_responses_per_hour", DEFAULT_POLICY["max_responses_per_hour"]),
            "max_responses_per_hour",
            1,
            240,
        ),
    }


def iso_now() -> str:
    """UTC timestamp in the form the audit log records."""
    return dt.datetime.now(tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def _requested(request: Mapping[str, Any], key: str) -> set[str]:
    """Read one selector list from a Context Pull Request.

    Selectors live under ``selectors`` in the signed request; a flat form is
    also accepted so callers can evaluate a hand-built request.
    """
    selectors = request.get("selectors")
    source = selectors if isinstance(selectors, Mapping) else request
    value = source.get(key)
    if not isinstance(value, list):
        return set()
    return {item for item in value if isinstance(item, str) and item}


def requester_of(request: Mapping[str, Any]) -> str:
    """The principal that signed the request."""
    for key in ("sender", "requester", "from"):
        value = request.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def correlation_of(request: Mapping[str, Any]) -> str:
    for key in ("request_id", "correlation_id"):
        value = request.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _hard_stops(
    request: Mapping[str, Any],
    plan: Mapping[str, Any],
    ledger_status: Mapping[str, Any],
) -> list[str]:
    """Conditions that always require a human, whatever the policy says."""
    stops: list[str] = []
    claims = plan.get("claims") or []

    # Semantic conflict: an unreconciled ledger has no single answer to give.
    heads = ledger_status.get("heads")
    if isinstance(heads, list):
        head_count = len(heads)
    elif isinstance(heads, int):
        head_count = heads
    else:
        head_count = 1
    if head_count > 1:
        stops.append("ledger has divergent heads; reconcile before answering")
    if ledger_status.get("open_conflicts"):
        stops.append("ledger has unresolved semantic conflicts")

    # Restricted sensitivity, whether asked for or actually selected.
    ceiling = request.get("max_sensitivity")
    if (
        isinstance(ceiling, str)
        and SENSITIVITY_RANK.get(ceiling, 0) > SENSITIVITY_RANK[AUTO_MAX_SENSITIVITY]
    ):
        stops.append("request asks for restricted context")
    for claim in claims:
        if not isinstance(claim, Mapping):
            stops.append("disclosure plan contains a malformed claim")
            break
        if (
            SENSITIVITY_RANK.get(str(claim.get("sensitivity", "internal")), 3)
            > (SENSITIVITY_RANK[AUTO_MAX_SENSITIVITY])
        ):
            stops.append("disclosure plan contains restricted context")
            break

    # Credential findings anywhere in scope.
    for excluded in plan.get("excluded") or []:
        if isinstance(excluded, Mapping) and SECRET_EXCLUSION_MARKER in str(
            excluded.get("reason", "")
        ):
            stops.append("secret scanner flagged in-scope context")
            break

    # Raw transcript text.
    for claim in claims:
        if not isinstance(claim, Mapping):
            continue
        provenance = claim.get("provenance")
        entries = provenance if isinstance(provenance, list) else []
        for entry in entries:
            kind = entry.get("type") if isinstance(entry, Mapping) else None
            if kind in TRANSCRIPT_PROVENANCE:
                stops.append("disclosure plan quotes a raw session transcript")
                break
        else:
            continue
        break
    return stops


def _relevance_gap(request: Mapping[str, Any], plan: Mapping[str, Any]) -> list[str]:
    """Find selected claims the request did not structurally ask for.

    Relevance for automation is structural only. Lexical overlap with the
    request's purpose is deliberately not accepted: a purpose of "the" shares a
    word with almost any statement, so word matching would authorize nearly
    anything. A human reading a plan can weigh prose; a standing authorization
    cannot.
    """
    wanted_kinds = _requested(request, "kinds")
    wanted_keys = _requested(request, "semantic_keys")
    wanted_labels = _requested(request, "labels")
    if not (wanted_kinds or wanted_keys or wanted_labels):
        # Nothing bounds such a request, so every claim it would receive is
        # unrequested by construction.
        return sorted(
            {
                str(claim.get("id", ""))
                for claim in plan.get("claims") or []
                if isinstance(claim, Mapping) and claim.get("id")
            }
        ) or ["(request declares no selectors)"]
    unrelated: list[str] = []
    for claim in plan.get("claims") or []:
        if not isinstance(claim, Mapping):
            continue
        labels = {item for item in claim.get("labels", []) if isinstance(item, str)}
        matched = (
            (wanted_kinds and claim.get("kind") in wanted_kinds)
            or (wanted_keys and claim.get("semantic_key") in wanted_keys)
            or (wanted_labels and bool(labels & wanted_labels))
        )
        if not matched:
            unrelated.append(str(claim.get("id", "")))
    return sorted({item for item in unrelated if item})


def evaluate(
    request: Mapping[str, Any],
    policy: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    ledger_status: Mapping[str, Any] | None = None,
    recent_responses: Iterable[str] = (),
    now: str | None = None,
) -> dict[str, Any]:
    """Decide whether this request may be answered without a human.

    Returns a record with `decision` of "auto" or "refer", the reasons behind
    it, and the exact gates that were evaluated. The record is written to the
    audit log verbatim, so a later reader can tell why an answer went out.
    """
    checked = load_policy(policy) if not policy.get("_validated") else dict(policy)
    status = ledger_status or {}
    moment = _parse_time(now) or dt.datetime.now(tz=dt.timezone.utc)

    blockers: list[str] = _hard_stops(request, plan, status)
    # Hard stops are reported even when automation is off, so `--dry-run`
    # explains everything standing in the way rather than only the first gate.
    if not checked["enabled"]:
        blockers.append("auto-respond is disabled for this project")

    requester = requester_of(request)
    if not requester:
        blockers.append("request has no identifiable requester")
    elif checked["allowed_peers"] and requester not in checked["allowed_peers"]:
        blockers.append("requester is not in the auto-respond peer allowlist")

    ceiling = request.get("max_sensitivity")
    if isinstance(ceiling, str) and ceiling in SENSITIVITY_RANK:
        if SENSITIVITY_RANK[ceiling] > SENSITIVITY_RANK[checked["max_sensitivity"]]:
            blockers.append("request exceeds the policy sensitivity ceiling")

    allowed_kinds = set(checked["allowed_kinds"])
    outside = sorted(_requested(request, "kinds") - allowed_kinds)
    if outside:
        blockers.append("request asks for kinds outside policy: " + ", ".join(outside))

    # The decisive check is on what would actually be disclosed.  A request may
    # declare no kinds at all, or select purely by label, and still pull claims
    # of a kind the policy never authorized.
    disclosed_outside = sorted(
        {
            str(claim.get("kind", ""))
            for claim in plan.get("claims") or []
            if isinstance(claim, Mapping) and claim.get("kind") not in allowed_kinds
        }
    )
    if disclosed_outside:
        blockers.append(
            "disclosure plan contains kinds outside policy: "
            + ", ".join(item or "(unknown)" for item in disclosed_outside)
        )

    denied = set(checked["denied_labels"])
    for claim in plan.get("claims") or []:
        if not isinstance(claim, Mapping):
            continue
        labels = {item for item in claim.get("labels", []) if isinstance(item, str)}
        hit = sorted(labels & denied)
        if hit:
            blockers.append("disclosure plan carries denied label: " + ", ".join(hit))
            break

    claims = plan.get("claims") or []
    if len(claims) > checked["max_claims"]:
        blockers.append("disclosure plan exceeds the policy claim ceiling")
    used = (plan.get("budget") or {}).get("used_bytes")
    if isinstance(used, int) and used > checked["max_bytes"]:
        blockers.append("disclosure plan exceeds the policy byte ceiling")

    unrelated = _relevance_gap(request, plan)
    if unrelated:
        blockers.append(
            "disclosure plan includes context the request did not ask for: "
            + ", ".join(unrelated[:5])
        )

    window = moment - dt.timedelta(hours=1)
    # An unreadable timestamp counts against the limit rather than being
    # dropped: a record that exists but cannot be dated is evidence an answer
    # was sent, and discarding it would widen the budget.
    recent = [
        item
        for item in recent_responses
        if (parsed := _parse_time(item)) is None or parsed > window
    ]
    if len(recent) >= checked["max_responses_per_hour"]:
        blockers.append("auto-respond rate limit reached for this hour")

    return {
        "decision": "refer" if blockers else "auto",
        "blockers": blockers,
        "requester": requester,
        "correlation_id": correlation_of(request),
        "claims": len(claims),
        "used_bytes": used if isinstance(used, int) else None,
        "responses_last_hour": len(recent),
        "policy": {
            "max_sensitivity": checked["max_sensitivity"],
            "allowed_kinds": checked["allowed_kinds"],
            "max_claims": checked["max_claims"],
            "max_bytes": checked["max_bytes"],
            "max_responses_per_hour": checked["max_responses_per_hour"],
        },
        "evaluated_at": moment.isoformat().replace("+00:00", "Z"),
    }
