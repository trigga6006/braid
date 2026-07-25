"""On-call incident handoff built entirely from existing Session Bridge parts.

The one job this module serves is the 3am handoff: an on-call agent asks a peer
endpoint for the confirmed facts, ruled-out hypotheses, open actions, blockers,
and recorded disagreements its own incident ledger is missing, then reads a
local brief while the answer sits in quarantine.

Three rules shape every function here:

*   A received response is data, never command authority.  Nothing in this
    module executes, deploys, writes source files, or otherwise acts on
    incoming claim content.  These functions queue one outbound request, read
    local state, and render text.
*   Responses stay quarantined.  ``ask`` composes the existing
    ``queue_request``/``sync`` path, so a fulfilled Context Pack lands in
    Context Ledger quarantine; promotion still requires the normal explicit
    review and acceptance commands.
*   A conflict is never resolved automatically.  ``build_brief`` and
    ``build_status`` print every side of a divergence and stop.

No new protocol, claim kind, claim field, ledger mutation, or selector
dimension is introduced.  This is a preset over ``context-pull-request/v1``
plus two read-only views.
"""

from __future__ import annotations

from pathlib import Path
import textwrap
from typing import Any, Mapping

import context_exchange as exchange
from context_model import CLAIM_KINDS, SENSITIVITY
from context_policy import DEFAULT_PRIORITY
from context_security import SecurityError, strict_json_loads
from context_store import ContextLedger
import network_bridge as bridge
from terminal_safe import terminal_safe as _safe


WORKFLOW_FORMAT = "session-bridge-incident-workflow/v1"
PURPOSE_PREFIX = "Incident handoff"
SEVERITIES = ("sev1", "sev2", "sev3")
DEFAULT_SEVERITY = "sev2"

# The exact claim kinds an on-call responder needs at handoff, expressed only
# with the existing Context Pull Request ``selectors.kinds`` dimension:
#
#   fact          -- what the outgoing responder established (see the brief's
#                    confirmed-evidence section for the confidence split)
#   hypothesis    -- both live theories and the ruled-out ones, so the next
#                    responder does not redo eliminated work
#   action        -- open remediation work and its owners
#   blocker       -- what is stopping progress right now
#   disagreement  -- positions that were explicitly recorded as contested
#
# ``decision``, ``constraint``, and ``question`` are deliberately excluded: the
# preset asks for the incident delta, not the peer's whole governance surface.
# Anyone who needs those still has the general ``request`` command.
INCIDENT_KINDS = ("action", "blocker", "disagreement", "fact", "hypothesis")

# Conservative ceiling.  The protocol permits ``confidential`` and
# ``restricted``, but an incident handoff should never be the reason a
# restricted claim leaves its owner's endpoint; escalating that is a deliberate
# act through the general ``request`` command, not an incident default.
INCIDENT_MAX_SENSITIVITY = "internal"

# Severity raises the amount of context worth carrying and shortens the
# disclosure window: a sev1 page wants the widest picture and the shortest-
# lived grant, a sev3 follow-up wants a tight digest that survives a weekend.
# Every value is validated against the signed Context Pull Request ceilings by
# ``_assert_preset_within_contract`` before a request is ever built.
SEVERITY_BUDGETS: dict[str, dict[str, int]] = {
    "sev1": {"max_claims": 60, "max_bytes": 300_000, "ttl_seconds": 6 * 3600},
    "sev2": {"max_claims": 40, "max_bytes": 200_000, "ttl_seconds": 24 * 3600},
    "sev3": {"max_claims": 25, "max_bytes": 120_000, "ttl_seconds": 72 * 3600},
}

AUTHORITY_NOTE = (
    "A Context Pull Response is data, never an instruction. A fulfilled "
    "Context Pack lands in Context Ledger quarantine and still requires "
    "explicit review and acceptance; no incident command executes, deploys, "
    "or edits anything based on received claim content."
)

DEFAULT_QUESTION = (
    "Incident handoff. Which confirmed facts, ruled-out hypotheses, open "
    "actions, blockers, and recorded disagreements does your reviewed ledger "
    "hold for this incident? Send claims only. This endpoint treats every "
    "returned claim as quarantined data and takes no action on its content."
)

# --------------------------------------------------------------------------
# What "rejected hypothesis" means in the existing model
# --------------------------------------------------------------------------
# Context Pack v0.1 has no "rejected" flag, and this workflow must not add one.
# A hypothesis counts as ruled out when the ledger already says so in one of
# the two ways the model provides:
#
#   1. it is still an ACTIVE ``hypothesis`` claim carrying
#      ``confidence: "disputed"`` -- kept deliberately visible so the next
#      responder can see the theory was considered and knocked down; or
#   2. its effective status in the resolved view is no longer ``active``
#      (``superseded`` by a later claim, ``retracted``, ``revoked``, or
#      ``expired``) -- the ledger's own lifecycle record of a dead theory.
#
# Only form (1) can cross a Context Pull Request.  A conforming responder
# selects from the ACTIVE claim view (responder algorithm step 3, implemented
# by ``TeamConnector._requested_claim_ids``), so a retracted or superseded
# claim is structurally unreachable over CPR v1, and a matching lifecycle
# removal is answered with ``needs-clarification`` instead of a partial delta.
# That is why ``incident ask`` selects the whole ``hypothesis`` kind -- CPR
# selectors are kinds, semantic keys, and labels only, with no confidence or
# status dimension -- and why the LOCAL ``incident brief``, reading its own
# history, is the surface that can additionally show form (2).
RULED_OUT_CONFIDENCE = "disputed"
RULED_OUT_STATUSES = ("superseded", "retracted", "revoked", "expired")

KNOWN_KINDS = ("fact", "decision", "constraint")
OPEN_KINDS = ("action", "blocker", "question")
OWNER_LABEL_PREFIX = "owner:"
MAX_QUARANTINE_BYTES = 4_000_000

# Exchange states that still need somebody: an inbound request nobody answered,
# an answer that has not left the outbox, an outbound request with no terminal
# response, or a delivery that permanently failed.
OPEN_EXCHANGE_STATES = {
    "inbound": ("open", "response-queued", "delivery-failed"),
    "outbound": ("queued", "sent", "delivery-failed"),
}


class IncidentWorkflowError(ValueError):
    """An incident workflow input or local ledger state is unusable."""


# --------------------------------------------------------------------------
# Preset
# --------------------------------------------------------------------------


def severity_budget(severity: str) -> dict[str, int]:
    """Return the claim, byte, and lifetime budget for one incident severity."""
    budget = SEVERITY_BUDGETS.get(str(severity))
    if budget is None:
        raise IncidentWorkflowError(
            "Incident severity must be one of: " + ", ".join(SEVERITIES)
        )
    return dict(budget)


def _assert_preset_within_contract(budget: Mapping[str, int]) -> None:
    """Fail closed if the preset ever drifts outside the signed CPR contract."""
    unknown = sorted(set(INCIDENT_KINDS) - set(CLAIM_KINDS))
    if unknown:
        raise IncidentWorkflowError(
            "Incident preset uses unknown claim kinds: " + ", ".join(unknown)
        )
    if len(INCIDENT_KINDS) > exchange.MAX_SELECTOR_ITEMS:
        raise IncidentWorkflowError("Incident preset exceeds the selector limit.")
    if INCIDENT_MAX_SENSITIVITY not in SENSITIVITY:
        raise IncidentWorkflowError("Incident sensitivity ceiling is invalid.")
    if not 1 <= int(budget["max_claims"]) <= exchange.MAX_REQUEST_CLAIMS:
        raise IncidentWorkflowError(
            "Incident claim budget exceeds the Context Pull Request ceiling."
        )
    if not 1 <= int(budget["max_bytes"]) <= exchange.MAX_REQUEST_BYTES:
        raise IncidentWorkflowError(
            "Incident byte budget exceeds the Context Pull Request ceiling."
        )
    if not 1 <= int(budget["ttl_seconds"]) <= exchange.MAX_LIFETIME_SECONDS:
        raise IncidentWorkflowError(
            "Incident request lifetime exceeds the Context Pull Request ceiling."
        )


def incident_request_preset(
    *,
    purpose: str,
    question: str | None = None,
    severity: str = DEFAULT_SEVERITY,
    since_revision: str | None = None,
) -> dict[str, Any]:
    """Return the curated incident selectors as plain Context Pull Request input."""
    budget = severity_budget(severity)
    _assert_preset_within_contract(budget)
    subject = str(purpose or "").strip()
    if not subject:
        raise IncidentWorkflowError("Incident purpose is required.")
    disclosure_purpose = f"{PURPOSE_PREFIX} ({severity}): {subject}"
    if len(disclosure_purpose) > exchange.MAX_PURPOSE_CHARS:
        room = exchange.MAX_PURPOSE_CHARS - (len(disclosure_purpose) - len(subject))
        raise IncidentWorkflowError(
            f"Incident purpose must be at most {room} characters."
        )
    text = str(question if question is not None else DEFAULT_QUESTION).strip()
    if not text or len(text) > exchange.MAX_QUESTION_CHARS:
        raise IncidentWorkflowError(
            f"Incident question must be 1 to {exchange.MAX_QUESTION_CHARS} characters."
        )
    return {
        "format": WORKFLOW_FORMAT,
        "severity": str(severity),
        "purpose": disclosure_purpose,
        "question": text,
        "kinds": list(INCIDENT_KINDS),
        # Empty means "no restriction on this dimension".  Semantic keys and
        # labels stay empty on purpose: a label selector is an intersection
        # test, so guessing the peer's taxonomy would silently drop the exact
        # claims the handoff needs.
        "semantic_keys": [],
        "labels": [],
        "since_revision": since_revision,
        "max_sensitivity": INCIDENT_MAX_SENSITIVITY,
        **budget,
    }


def is_incident_request(record: Mapping[str, Any]) -> bool:
    """Recognize a request produced by this preset from its signed fields."""
    selectors = record.get("selectors")
    kinds = selectors.get("kinds", []) if isinstance(selectors, Mapping) else []
    return sorted(str(kind) for kind in kinds) == sorted(INCIDENT_KINDS) and str(
        record.get("purpose", "")
    ).startswith(PURPOSE_PREFIX)


def ask(
    connector: Any,
    project: str,
    *,
    recipient: str,
    purpose: str,
    question: str | None = None,
    severity: str = DEFAULT_SEVERITY,
    since_revision: str | None = None,
) -> dict[str, Any]:
    """Queue the incident preset as an ordinary signed Context Pull Request.

    Trust binding, recipient binding, credential scanning, signing, and the
    budget ceilings are all enforced by ``TeamConnector.queue_request``; this
    function only chooses the selectors.
    """
    preset = incident_request_preset(
        purpose=purpose,
        question=question,
        severity=severity,
        since_revision=since_revision,
    )
    queued = connector.queue_request(
        project,
        recipient=recipient,
        purpose=preset["purpose"],
        question=preset["question"],
        kinds=list(preset["kinds"]),
        semantic_keys=None,
        labels=None,
        since_revision=preset["since_revision"],
        max_sensitivity=preset["max_sensitivity"],
        max_claims=preset["max_claims"],
        max_bytes=preset["max_bytes"],
        ttl_seconds=preset["ttl_seconds"],
    )
    return {
        "workflow": "incident-ask",
        "severity": preset["severity"],
        "preset": {
            "kinds": list(preset["kinds"]),
            "max_sensitivity": preset["max_sensitivity"],
            "max_claims": preset["max_claims"],
            "max_bytes": preset["max_bytes"],
            "ttl_seconds": preset["ttl_seconds"],
        },
        "authority": AUTHORITY_NOTE,
        "next_step": (
            "Run sync to deliver the request and to receive any answer into "
            "quarantine, then review and accept it explicitly."
        ),
        **queued,
    }


# --------------------------------------------------------------------------
# Shared claim helpers
# --------------------------------------------------------------------------


def _effective_status(claim: Mapping[str, Any]) -> str:
    return str(claim.get("effective_status", claim.get("status", "active")))


def _observed_at(claim: Mapping[str, Any]) -> str:
    freshness = claim.get("freshness")
    if isinstance(freshness, Mapping):
        return str(freshness.get("observed_at", ""))
    return ""


def hypothesis_disposition(claim: Mapping[str, Any]) -> str:
    """Return ``ruled-out`` or ``open`` for one hypothesis claim."""
    if _effective_status(claim) in RULED_OUT_STATUSES:
        return "ruled-out"
    if str(claim.get("confidence")) == RULED_OUT_CONFIDENCE:
        return "ruled-out"
    return "open"


def rejection_reason(claim: Mapping[str, Any]) -> str:
    """Explain, in the model's own vocabulary, why a hypothesis is ruled out."""
    status = _effective_status(claim)
    if status in RULED_OUT_STATUSES:
        return status
    return f"confidence={RULED_OUT_CONFIDENCE}"


def _sorted_claims(claims: list[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Order by the existing disclosure priority, newest evidence first."""
    items = sorted(claims, key=lambda claim: str(claim.get("id", "")))
    items.sort(key=_observed_at, reverse=True)
    items.sort(key=lambda claim: -DEFAULT_PRIORITY.get(str(claim.get("kind")), 0))
    return items


def _owners(
    claim: Mapping[str, Any], origin: Mapping[str, dict[str, Any]]
) -> list[str]:
    """Derive owners from existing data only: ``owner:`` labels, else authors."""
    labelled = []
    for label in claim.get("labels", []) or []:
        text = str(label)
        if text.lower().startswith(OWNER_LABEL_PREFIX):
            name = text[len(OWNER_LABEL_PREFIX) :].strip()
            if name:
                labelled.append(name)
    if labelled:
        return sorted(set(labelled))
    record = origin.get(str(claim.get("id", "")))
    return list(record["authors"]) if record else []


def _evidence(claim: Mapping[str, Any]) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for source in claim.get("provenance", []) or []:
        if not isinstance(source, Mapping):
            continue
        entries.append(
            {
                "type": str(source.get("type", "")),
                "uri": str(source.get("uri", "")),
                "observed_at": str(source.get("observed_at", "")),
                "digest": str(source.get("digest") or ""),
            }
        )
    return entries


def _summary(
    claim: Mapping[str, Any], origin: Mapping[str, dict[str, Any]]
) -> dict[str, Any]:
    claim_id = str(claim.get("id", ""))
    record = origin.get(claim_id, {})
    return {
        "id": claim_id,
        "kind": str(claim.get("kind", "")),
        "semantic_key": str(claim.get("semantic_key", "")),
        "statement": str(claim.get("statement", "")),
        "confidence": str(claim.get("confidence", "")),
        "sensitivity": str(claim.get("sensitivity", "internal")),
        "status": _effective_status(claim),
        "labels": [str(label) for label in claim.get("labels", []) or []],
        "supersedes": [str(item) for item in claim.get("supersedes", []) or []],
        "observed_at": _observed_at(claim),
        "priority": DEFAULT_PRIORITY.get(str(claim.get("kind")), 0),
        "owners": _owners(claim, origin),
        "evidence": _evidence(claim),
        "revision": str(record.get("revision", "")),
    }


def _claim_origin(ledger: Any) -> dict[str, dict[str, Any]]:
    """Map each claim to the newest reviewed revision that carried it."""
    origin: dict[str, dict[str, Any]] = {}
    for revision in reversed(ledger.log()):
        authors = [
            str(author.get("principal_id", ""))
            for author in revision.get("authors", [])
            if isinstance(author, Mapping)
        ]
        for claim in revision.get("claims", []):
            origin[str(claim.get("id", ""))] = {
                "revision": str(revision.get("id", "")),
                "authors": [author for author in authors if author],
            }
    return origin


def _scoped_ids(
    ledger: Any, heads: list[str], since_revision: str | None
) -> set[str] | None:
    if since_revision is None:
        return None
    if len(heads) != 1:
        raise IncidentWorkflowError(
            "The ledger has divergent heads; reconcile them before requesting a "
            "revision-scoped brief."
        )
    try:
        delta = ledger.diff(str(since_revision), heads[0])
    except (PermissionError, ValueError) as error:
        raise IncidentWorkflowError(
            f"Baseline revision is not available in this ledger: {since_revision}"
        ) from error
    scoped = {str(claim["id"]) for claim in delta["added"]}
    scoped |= {str(change["after"]["id"]) for change in delta["changed"]}
    scoped |= {str(claim["id"]) for claim in delta["removed"]}
    scoped |= {str(item["id"]) for item in delta["lifecycle"]}
    return scoped


# --------------------------------------------------------------------------
# Brief
# --------------------------------------------------------------------------


def build_brief(
    ledger: Any,
    *,
    project: str | None = None,
    ledger_project: str | None = None,
    since_revision: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    """Return a read-only on-call handoff brief for the local reviewed ledger.

    This function never stages, commits, accepts, resolves, or mutates
    anything; it only reads the resolved claim view and the current conflict
    view.
    """
    status = ledger.status()
    heads = [str(head) for head in status["heads"]]
    view = ledger.freshness(now)
    all_active = list(view["active_claims"])
    all_historical = list(view["historical_claims"])
    origin = _claim_origin(ledger)
    superseded_by: dict[str, list[str]] = {}
    for claim in all_active:
        for target in claim.get("supersedes", []) or []:
            superseded_by.setdefault(str(target), []).append(str(claim["id"]))

    scoped = _scoped_ids(ledger, heads, since_revision)
    if scoped is None:
        active, historical = all_active, all_historical
    else:
        active = [claim for claim in all_active if str(claim["id"]) in scoped]
        historical = [claim for claim in all_historical if str(claim["id"]) in scoped]

    known, unconfirmed, open_items = [], [], []
    open_hypotheses, ruled_out = [], []
    for claim in active:
        kind = str(claim.get("kind"))
        if kind in KNOWN_KINDS:
            target = (
                known if str(claim.get("confidence")) == "confirmed" else unconfirmed
            )
            target.append(claim)
        elif kind in OPEN_KINDS:
            open_items.append(claim)
        elif kind == "hypothesis":
            bucket = (
                ruled_out
                if hypothesis_disposition(claim) == "ruled-out"
                else open_hypotheses
            )
            bucket.append(claim)
    ruled_out.extend(
        claim for claim in historical if str(claim.get("kind")) == "hypothesis"
    )

    ruled_out_records = []
    for claim in _sorted_claims(ruled_out):
        record = _summary(claim, origin)
        record["ruled_out_because"] = rejection_reason(claim)
        record["superseded_by"] = sorted(superseded_by.get(record["id"], []))
        ruled_out_records.append(record)

    sections = {
        "known": [_summary(claim, origin) for claim in _sorted_claims(known)],
        "unconfirmed": [
            _summary(claim, origin) for claim in _sorted_claims(unconfirmed)
        ],
        "ruled_out": ruled_out_records,
        "open_hypotheses": [
            _summary(claim, origin) for claim in _sorted_claims(open_hypotheses)
        ],
        "open": [_summary(claim, origin) for claim in _sorted_claims(open_items)],
        "disagreements": _disagreements(active, all_active, origin),
    }
    return {
        "format": WORKFLOW_FORMAT,
        "workflow": "incident-brief",
        "project": project,
        "ledger_project": ledger_project or getattr(ledger, "project", None),
        "heads": heads,
        "since_revision": since_revision,
        "as_of": str(view.get("as_of", "")),
        "read_only": True,
        "authority": AUTHORITY_NOTE,
        "sections": sections,
        "unresolved_conflicts": _unresolved_conflicts(ledger, origin),
        "counts": {name: len(items) for name, items in sections.items()},
    }


def _disagreements(
    active: list[Mapping[str, Any]],
    all_active: list[Mapping[str, Any]],
    origin: Mapping[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Group contested semantic keys, keeping every position intact.

    Two shapes count as an unresolved disagreement: an explicit
    ``disagreement`` claim, and two or more active claims that say different
    things about the same semantic key.  Neither is collapsed into a winner.
    """
    by_key: dict[str, list[Mapping[str, Any]]] = {}
    for claim in all_active:
        by_key.setdefault(str(claim.get("semantic_key", "")), []).append(claim)
    in_scope = {str(claim["id"]) for claim in active}
    records: list[dict[str, Any]] = []
    for key in sorted(by_key):
        group = by_key[key]
        if not any(str(claim["id"]) in in_scope for claim in group):
            continue
        recorded = [
            claim for claim in group if str(claim.get("kind")) == "disagreement"
        ]
        positions = [
            claim for claim in group if str(claim.get("kind")) != "disagreement"
        ]
        distinct = {
            (str(claim.get("statement")), str(claim.get("confidence")))
            for claim in positions
        }
        if not recorded and len(distinct) < 2:
            continue
        records.append(
            {
                "semantic_key": key,
                "source": (
                    "disagreement-claim" if recorded else "divergent-active-claims"
                ),
                "recorded_by": [
                    _summary(claim, origin) for claim in _sorted_claims(recorded)
                ],
                "positions": [
                    _summary(claim, origin) for claim in _sorted_claims(positions)
                ],
                "resolution": "none; both positions stand until a human decides",
            }
        )
    return records


def _unresolved_conflicts(
    ledger: Any, origin: Mapping[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Surface durable two-head merge conflicts without picking a side."""
    view = ledger.conflicts()
    return [
        {
            "id": str(conflict.get("id", "")),
            "status": str(conflict.get("status", "unresolved")),
            "semantic_key": str(conflict.get("semantic_key", "")),
            "reason": str(conflict.get("reason", "")),
            "local": [
                _summary(claim, origin)
                for claim in _sorted_claims(list(conflict.get("local_claims", [])))
            ],
            "remote": [
                _summary(claim, origin)
                for claim in _sorted_claims(list(conflict.get("remote_claims", [])))
            ],
        }
        for conflict in view.get("conflicts", [])
    ]


# --------------------------------------------------------------------------
# Brief rendering
# --------------------------------------------------------------------------

_RULE = "=" * 72
_THIN = "-" * 72


def _claim_lines(record: Mapping[str, Any], *, evidence: bool = False) -> list[str]:
    """Render one claim.

    Every value here was authored somewhere else -- a peer endpoint, an
    imported pack, an ``owner:`` label -- and none of it is validated for
    control characters.  ``_safe`` escapes them so a statement carrying a
    newline cannot forge an extra line of what looks like our own output, and
    an ESC sequence cannot repaint the on-call reader's terminal.
    """
    header = (
        f"  [{_safe(record['kind'])}] {_safe(record['semantic_key'])}  "
        f"confidence={_safe(record['confidence'])}  claim={_safe(record['id'])}"
    )
    lines = [header, f"    {_safe(record['statement'])}"]
    if record.get("ruled_out_because"):
        lines.append(f"    ruled out: {_safe(record['ruled_out_because'])}")
    if record.get("superseded_by"):
        superseded = ", ".join(_safe(item) for item in record["superseded_by"])
        lines.append(f"    superseded by: {superseded}")
    if evidence:
        for source in record.get("evidence", [])[:4]:
            observed = (
                f" ({_safe(source['observed_at'])})" if source["observed_at"] else ""
            )
            lines.append(
                f"    evidence: {_safe(source['type'])} "
                f"{_safe(source['uri'])}{observed}"
            )
    if record.get("owners"):
        owners = ", ".join(_safe(owner) for owner in record["owners"])
        lines.append(f"    owners: {owners}")
    return lines


def _section(
    title: str, records: list[Mapping[str, Any]], *, evidence: bool = False
) -> list[str]:
    lines = [f"{title} ({len(records)})", _THIN]
    if not records:
        lines.append("  (none)")
    for record in records:
        lines.extend(_claim_lines(record, evidence=evidence))
    lines.append("")
    return lines


def render_brief(brief: Mapping[str, Any]) -> str:
    """Render the brief as the plain text an on-call human reads at 3am."""
    sections = brief["sections"]
    heads = brief.get("heads") or []
    baseline = brief.get("since_revision")
    head_text = (
        ", ".join(_safe(head) for head in heads) if heads else "(no reviewed head)"
    )
    lines = [
        _RULE,
        " INCIDENT HANDOFF BRIEF",
        f" team project:   {_safe(brief.get('project') or '-')}",
        f" ledger project: {_safe(brief.get('ledger_project') or '-')}",
        f" head revision:  {head_text}",
        f" baseline:       {_safe(baseline or '(full reviewed ledger)')}",
        f" as of:          {_safe(brief.get('as_of') or '-')}",
        _RULE,
        "",
    ]
    lines.extend(
        _section(
            "WHAT WE KNOW -- confirmed, with evidence", sections["known"], evidence=True
        )
    )
    lines.extend(_section("NOT YET CONFIRMED", sections["unconfirmed"]))
    lines.extend(
        _section(
            "WHAT WE RULED OUT -- do not redo this work",
            sections["ruled_out"],
            evidence=True,
        )
    )
    lines.extend(_section("STILL BEING TESTED", sections["open_hypotheses"]))
    lines.extend(
        _section("STILL OPEN -- actions, blockers, questions", sections["open"])
    )

    disagreements = sections["disagreements"]
    lines.append(
        f"UNRESOLVED DISAGREEMENT -- both positions stand ({len(disagreements)})"
    )
    lines.append(_THIN)
    if not disagreements:
        lines.append("  (none)")
    for record in disagreements:
        lines.append(
            f"  semantic key: {_safe(record['semantic_key'])}  "
            f"[{_safe(record['source'])}]"
        )
        for claim in record["recorded_by"]:
            lines.append(
                f"    recorded by {_safe(claim['id'])}: {_safe(claim['statement'])}"
            )
        for index, claim in enumerate(record["positions"], start=1):
            owners = (
                " (" + ", ".join(_safe(owner) for owner in claim["owners"]) + ")"
                if claim["owners"]
                else ""
            )
            lines.append(
                f"    position {index} [{_safe(claim['kind'])}] "
                f"{_safe(claim['id'])}{owners}: {_safe(claim['statement'])}"
            )
        lines.append(f"    {_safe(record['resolution'])}")
    lines.append("")

    conflicts = brief.get("unresolved_conflicts") or []
    lines.append(f"UNRESOLVED LEDGER CONFLICTS -- needs a human ({len(conflicts)})")
    lines.append(_THIN)
    if not conflicts:
        lines.append("  (none)")
    for conflict in conflicts:
        lines.append(
            f"  {_safe(conflict['id'])}  "
            f"semantic key: {_safe(conflict['semantic_key'])}"
        )
        for claim in conflict["local"]:
            lines.append(
                f"    local  [{_safe(claim['kind'])}] {_safe(claim['id'])}: "
                f"{_safe(claim['statement'])}"
            )
        for claim in conflict["remote"]:
            lines.append(
                f"    remote [{_safe(claim['kind'])}] {_safe(claim['id'])}: "
                f"{_safe(claim['statement'])}"
            )
        lines.append(f"    {_safe(conflict['reason'])}")
    lines.append("")
    lines.append(_THIN)
    lines.append(
        textwrap.fill(
            _safe(brief["authority"]),
            width=len(_THIN),
            initial_indent="  ",
            subsequent_indent="  ",
        )
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Status
# --------------------------------------------------------------------------


def _quarantined_responses(
    ledger: Any, tokens_by_request: Mapping[str, str]
) -> list[dict[str, Any]]:
    """List packs awaiting review without echoing their unreviewed statements.

    Only counts, kinds, and the authoring key are reported.  Reading the actual
    statements is the explicit Context Ledger review step, which redacts
    credential findings first; a triage view must not become a side channel
    that prints unreviewed remote text.
    """
    request_by_token = {
        str(token): request_id for request_id, token in tokens_by_request.items()
    }
    records: list[dict[str, Any]] = []
    quarantine = getattr(ledger, "quarantine", None)
    if not isinstance(quarantine, Path) or not quarantine.exists():
        return records
    for path in sorted(quarantine.glob("*.json")):
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise IncidentWorkflowError(
                f"Unable to read quarantined response: {path.name}"
            ) from error
        if len(raw) > MAX_QUARANTINE_BYTES:
            raise IncidentWorkflowError(
                f"Quarantined response exceeds the safety limit: {path.name}"
            )
        try:
            item = strict_json_loads(raw)
        except SecurityError as error:
            raise IncidentWorkflowError(
                f"Quarantined response is unreadable: {path.name}"
            ) from error
        if not isinstance(item, dict):
            raise IncidentWorkflowError(
                f"Quarantined response is unreadable: {path.name}"
            )
        review = item.get("review") if isinstance(item.get("review"), dict) else {}
        claims = review.get("claims") if isinstance(review.get("claims"), list) else []
        records.append(
            {
                "token": path.stem,
                "source_name": str(item.get("source_name", "")),
                "imported_at": str(item.get("imported_at", "")),
                "reviewed": bool(item.get("reviewed_at")),
                "accepted": False,
                "author_key_id": str(review.get("author_key_id", "")),
                "claim_count": review.get("claim_count"),
                "kinds": sorted(
                    {
                        str(claim.get("kind", ""))
                        for claim in claims
                        if isinstance(claim, Mapping)
                    }
                ),
                "security_findings": len(review.get("security_findings", []) or []),
                "request_id": request_by_token.get(path.stem),
                "next_step": (
                    "Review and accept this pack explicitly through the Context "
                    "Ledger review path; incident commands never auto-accept."
                ),
            }
        )
    return records


def build_status(
    connector: Any, project: str, ledger_project: str, *, ledger: Any = None
) -> dict[str, Any]:
    """Show open incident exchange state that still needs a human."""
    if ledger is None:
        ledger = ContextLedger(ledger_project, connector.home)
    listing = connector.requests(project)["requests"]
    pending: list[dict[str, Any]] = []
    tokens_by_request: dict[str, str] = {}
    for record in listing:
        direction = str(record.get("direction", ""))
        state = str(record.get("state", ""))
        request_id = str(record.get("request_id", ""))
        token = _quarantine_token(connector, project, direction, request_id)
        if token:
            tokens_by_request[request_id] = token
        if state not in OPEN_EXCHANGE_STATES.get(direction, ()):
            continue
        pending.append(
            {
                "direction": direction,
                "state": state,
                "request_id": request_id,
                "peer": record.get("peer"),
                "purpose": record.get("purpose"),
                "selectors": record.get("selectors"),
                "since_revision": record.get("since_revision"),
                "max_sensitivity": record.get("max_sensitivity"),
                "created_at": record.get("created_at"),
                "expires_at": record.get("expires_at"),
                "incident_preset": is_incident_request(record),
            }
        )
    quarantined = _quarantined_responses(ledger, tokens_by_request)
    conflicts = _unresolved_conflicts(ledger, _claim_origin(ledger))
    return {
        "format": WORKFLOW_FORMAT,
        "workflow": "incident-status",
        "project": project,
        "ledger_project": ledger_project,
        "heads": [str(head) for head in ledger.status()["heads"]],
        "pending_requests": pending,
        "quarantined_responses": quarantined,
        "unresolved_conflicts": conflicts,
        "needs_human": bool(pending or quarantined or conflicts),
        "authority": AUTHORITY_NOTE,
    }


def _quarantine_token(
    connector: Any, project: str, direction: str, request_id: str
) -> str | None:
    """Read the quarantine token an existing exchange record already stores."""
    if direction != "outbound" or not request_id:
        return None
    try:
        path = connector.exchange_state_path(project, direction, request_id)
    except ValueError:
        return None
    if not path.exists():
        return None
    state = bridge.load_protected_json(path)
    token = state.get("quarantine_token")
    return str(token) if isinstance(token, str) and token else None
