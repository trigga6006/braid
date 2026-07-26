"""Immutable, provenance-preserving Context Pack v0.1 semantic model.

This module intentionally has no transport, filesystem, or model dependency.  It
is the validation boundary used before a context pack crosses a trust boundary.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


FORMAT = "context-pack/v0.1"
MAX_REVISION_BYTES = 1_000_000
MAX_CLAIMS = 500
MAX_PROVENANCE_PER_CLAIM = 32
MAX_PARENTS = 2
MAX_PARENT_DEPTH = 64
MAX_STATEMENT_CHARS = 20_000
MAX_ARTIFACTS = 128

CLAIM_KINDS = frozenset(
    {
        "fact",
        "decision",
        "constraint",
        "hypothesis",
        "question",
        "action",
        "blocker",
        "disagreement",
    }
)
CLAIM_STATUSES = frozenset({"active", "superseded", "retracted", "expired", "revoked"})
CONFIDENCE = frozenset({"confirmed", "likely", "tentative", "disputed"})
SENSITIVITY = frozenset({"public", "internal", "confidential", "restricted"})
PROVENANCE_TYPES = frozenset(
    {
        "repository_file",
        "test_result",
        "command_output",
        "human_statement",
        "remote_agent",
        "external_source",
        "transcript_excerpt",
    }
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class ContextValidationError(ValueError):
    """Input does not meet the portable Context Pack v0.1 contract."""


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def canonical_json(value: Any) -> bytes:
    """Return the sole byte representation used for hashing Context Pack data."""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ContextValidationError(f"Value is not canonical JSON: {error}") from error


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContextValidationError(f"{name} must be an object")
    return value


def _require_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ContextValidationError(f"{name} must be a 1-128 character identifier")
    return value


def _require_text(value: Any, name: str, maximum: int = MAX_STATEMENT_CHARS) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ContextValidationError(f"{name} must contain 1-{maximum} characters")
    return value


def _parse_time(value: Any, name: str) -> datetime:
    if not isinstance(value, str):
        raise ContextValidationError(f"{name} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ContextValidationError(f"{name} must be an RFC3339 timestamp") from error
    if parsed.tzinfo is None:
        raise ContextValidationError(f"{name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _claim_payload(claim: Mapping[str, Any]) -> dict[str, Any]:
    """Stable content identity excludes transport/UI-only fields."""
    return {
        key: copy.deepcopy(value)
        for key, value in claim.items()
        if key not in {"id", "display"}
    }


def claim_fingerprint(claim: Mapping[str, Any]) -> str:
    validate_claim(claim)
    return digest(_claim_payload(claim))


def make_claim(
    claim_id: str,
    kind: str,
    statement: str,
    semantic_key: str,
    provenance: list[dict[str, Any]],
    *,
    confidence: str = "likely",
    observed_at: str | None = None,
    expires_at: str | None = None,
    labels: list[str] | None = None,
    supersedes: list[str] | None = None,
    sensitivity: str = "internal",
    audience: list[str] | None = None,
) -> dict[str, Any]:
    claim = {
        "id": claim_id,
        "kind": kind,
        "status": "active",
        "statement": statement,
        "semantic_key": semantic_key,
        "confidence": confidence,
        "freshness": {
            "observed_at": observed_at or utc_now(),
            "expires_at": expires_at,
        },
        "provenance": provenance,
        "labels": labels or [],
        "supersedes": supersedes or [],
        "conflicts_with": [],
        "redactions": [],
        "sensitivity": sensitivity,
        "audience": audience or [],
    }
    validate_claim(claim)
    return claim


def validate_claim(claim: Mapping[str, Any]) -> None:
    _require_mapping(claim, "claim")
    _require_id(claim.get("id"), "claim.id")
    if claim.get("kind") not in CLAIM_KINDS:
        raise ContextValidationError("claim.kind is unsupported")
    if claim.get("status") not in CLAIM_STATUSES:
        raise ContextValidationError("claim.status is unsupported")
    _require_text(claim.get("statement"), "claim.statement")
    _require_id(claim.get("semantic_key"), "claim.semantic_key")
    if claim.get("confidence") not in CONFIDENCE:
        raise ContextValidationError("claim.confidence is unsupported")
    if claim.get("sensitivity", "internal") not in SENSITIVITY:
        raise ContextValidationError("claim.sensitivity is unsupported")
    freshness = _require_mapping(claim.get("freshness"), "claim.freshness")
    observed = _parse_time(freshness.get("observed_at"), "claim.freshness.observed_at")
    expires = freshness.get("expires_at")
    if (
        expires is not None
        and _parse_time(expires, "claim.freshness.expires_at") <= observed
    ):
        raise ContextValidationError("claim freshness expiry must be after observation")
    provenance = claim.get("provenance")
    if (
        not isinstance(provenance, list)
        or not provenance
        or len(provenance) > MAX_PROVENANCE_PER_CLAIM
    ):
        raise ContextValidationError("claim.provenance must contain 1-32 entries")
    for index, source in enumerate(provenance):
        source = _require_mapping(source, f"claim.provenance[{index}]")
        if source.get("type") not in PROVENANCE_TYPES:
            raise ContextValidationError("claim provenance type is unsupported")
        _require_text(source.get("uri"), "claim provenance uri", 4096)
        if source.get("digest") is not None and (
            not isinstance(source["digest"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", source["digest"]) is None
        ):
            raise ContextValidationError(
                "claim provenance digest must be sha256 when supplied"
            )
        _parse_time(source.get("observed_at"), "claim provenance observed_at")
    if claim["confidence"] == "confirmed" and all(
        item.get("type") == "human_statement" for item in provenance
    ):
        raise ContextValidationError(
            "confirmed claims need non-human-statement provenance"
        )
    for field in ("labels", "supersedes", "conflicts_with", "redactions", "audience"):
        value = claim.get(field, [])
        if (
            not isinstance(value, list)
            or len(value) > 128
            or not all(isinstance(item, str) and item for item in value)
        ):
            raise ContextValidationError(
                f"claim.{field} must be a bounded list of strings"
            )


def _revision_unsigned(revision: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value)
        for key, value in revision.items()
        if key != "integrity"
    }


def create_revision(
    pack_id: str,
    revision_id: str,
    sequence: int,
    parent_ids: list[str],
    claims: list[dict[str, Any]],
    authors: list[dict[str, Any]],
    governance: dict[str, Any],
    message: str,
    *,
    scope: dict[str, Any] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    revision = {
        "format": FORMAT,
        "id": _require_id(revision_id, "revision.id"),
        "pack_id": _require_id(pack_id, "pack_id"),
        "scope": scope
        or {"id": pack_id, "purpose": "General context exchange", "project": ""},
        "revision": {
            "id": revision_id,
            "parent_ids": parent_ids,
            "sequence": sequence,
            "created_at": created_at or utc_now(),
        },
        "authors": copy.deepcopy(authors),
        "governance": copy.deepcopy(governance),
        "message": message,
        "claims": copy.deepcopy(claims),
        "artifacts": copy.deepcopy(artifacts or []),
    }
    _validate_revision_shape(revision, known_revisions=None)
    revision["integrity"] = {
        "canonical_sha256": digest(_revision_unsigned(revision)),
        "signature": None,
    }
    return revision


def _validate_revision_shape(
    revision: Mapping[str, Any], known_revisions: Mapping[str, Mapping[str, Any]] | None
) -> None:
    if revision.get("format") != FORMAT:
        raise ContextValidationError("unsupported Context Pack format")
    _require_id(revision.get("id"), "revision.id")
    _require_id(revision.get("pack_id"), "pack_id")
    scope = _require_mapping(revision.get("scope"), "scope")
    _require_id(scope.get("id"), "scope.id")
    _require_text(scope.get("purpose"), "scope.purpose", 500)
    if not isinstance(scope.get("project"), str) or len(scope["project"]) > 500:
        raise ContextValidationError("scope.project is invalid")
    meta = _require_mapping(revision.get("revision"), "revision")
    if meta.get("id") != revision.get("id"):
        raise ContextValidationError("revision.id must match top-level id")
    parents = meta.get("parent_ids")
    if (
        not isinstance(parents, list)
        or len(parents) > MAX_PARENTS
        or len(set(parents)) != len(parents)
    ):
        raise ContextValidationError(
            "revision parent_ids must have at most two distinct entries"
        )
    for parent in parents:
        _require_id(parent, "revision parent id")
        if parent == revision["id"]:
            raise ContextValidationError("revision cannot be its own parent")
    if not isinstance(meta.get("sequence"), int) or meta["sequence"] < 1:
        raise ContextValidationError("revision sequence must be positive")
    _parse_time(meta.get("created_at"), "revision.created_at")
    _require_text(revision.get("message"), "revision.message", 500)
    authors = revision.get("authors")
    if not isinstance(authors, list) or not authors:
        raise ContextValidationError("revision must name at least one author")
    for author in authors:
        author = _require_mapping(author, "author")
        _require_text(author.get("principal_id"), "author.principal_id", 512)
        _require_text(author.get("display_name"), "author.display_name", 256)
        if author.get("role") not in {"owner", "contributor", "importer"}:
            raise ContextValidationError("author.role is unsupported")
    governance = _require_mapping(revision.get("governance"), "governance")
    _require_text(
        governance.get("owner_principal_id"), "governance.owner_principal_id", 512
    )
    if governance.get("visibility") not in {
        "private",
        "scoped",
        "shared",
    } or governance.get("share_policy") not in {
        "owner_approval",
        "all_authors",
        "deny",
    }:
        raise ContextValidationError("governance is unsupported")
    recipients = governance.get("recipients")
    if not isinstance(recipients, list) or not all(
        isinstance(item, str) and item for item in recipients
    ):
        raise ContextValidationError("governance.recipients is invalid")
    claims = revision.get("claims")
    if not isinstance(claims, list) or len(claims) > MAX_CLAIMS:
        raise ContextValidationError("revision claims exceed the limit")
    claim_ids: set[str] = set()
    for claim in claims:
        validate_claim(claim)
        if claim["id"] in claim_ids:
            raise ContextValidationError("revision contains duplicate claim IDs")
        claim_ids.add(claim["id"])
    artifacts = revision.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) > MAX_ARTIFACTS:
        raise ContextValidationError("revision artifacts exceed the limit")
    for artifact in artifacts:
        artifact = _require_mapping(artifact, "artifact")
        _require_id(artifact.get("id"), "artifact.id")
        _require_text(artifact.get("media_type"), "artifact.media_type", 256)
        _require_text(artifact.get("uri"), "artifact.uri", 4096)
        if (
            not isinstance(artifact.get("digest"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"]) is None
        ):
            raise ContextValidationError("artifact.digest must be sha256")
    if known_revisions is not None:
        for parent in parents:
            if parent not in known_revisions:
                raise ContextValidationError(f"unknown parent revision: {parent}")
        if parents:
            if (
                meta["sequence"]
                != max(
                    int(known_revisions[parent]["revision"]["sequence"])
                    for parent in parents
                )
                + 1
            ):
                raise ContextValidationError(
                    "revision sequence must directly follow its parent"
                )
        elif meta["sequence"] != 1:
            raise ContextValidationError("root revision sequence must be 1")
        if _ancestry_depth(revision["id"], parents, known_revisions) > MAX_PARENT_DEPTH:
            raise ContextValidationError("revision ancestry exceeds maximum depth")


def _ancestry_depth(
    revision_id: str, parents: list[str], known: Mapping[str, Mapping[str, Any]]
) -> int:
    def visit(current: str, seen: set[str]) -> int:
        if current in seen:
            raise ContextValidationError("revision graph contains a cycle")
        item = known.get(current)
        if not item:
            return 0
        next_seen = seen | {current}
        return 1 + max(
            (visit(parent, next_seen) for parent in item["revision"]["parent_ids"]),
            default=0,
        )

    return max((visit(parent, {revision_id}) for parent in parents), default=0)


def validate_revision(
    revision: Mapping[str, Any],
    known_revisions: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    _validate_revision_shape(revision, known_revisions)
    integrity = _require_mapping(revision.get("integrity"), "integrity")
    expected = digest(_revision_unsigned(revision))
    if integrity.get("canonical_sha256") != expected:
        raise ContextValidationError("revision digest mismatch")
    if len(canonical_json(revision)) > MAX_REVISION_BYTES:
        raise ContextValidationError("revision exceeds byte limit")


def _ordered(revisions: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    items = list(revisions)
    known = {str(item.get("id")): item for item in items}
    for item in items:
        validate_revision(item, known)
    return sorted(
        items, key=lambda item: (int(item["revision"]["sequence"]), str(item["id"]))
    )


def _is_expired(claim: Mapping[str, Any], now: datetime) -> bool:
    expiry = claim["freshness"].get("expires_at")
    return (
        expiry is not None and _parse_time(expiry, "claim.freshness.expires_at") <= now
    )


def resolved_active_view(
    revisions: Iterable[Mapping[str, Any]], now: str | None = None
) -> dict[str, Any]:
    """Resolve immutable history without mutating a claim's committed status."""
    current = _parse_time(now, "now") if now else datetime.now(timezone.utc)
    claims: dict[str, dict[str, Any]] = {}
    for revision in _ordered(revisions):
        for claim in revision["claims"]:
            claims[claim["id"]] = copy.deepcopy(claim)
    # Supersession propagates transitively from every effectively-active claim
    # through its supersedes edges (including via expired intermediates): a live
    # claim makes its whole ancestor chain obsolete.  But an expired/dead
    # override with no live successor is NOT a seed, so it cannot on its own keep
    # hiding the still-true fact beneath it (which would drop the current fact).
    live_seeds = [
        claim
        for claim in claims.values()
        if claim.get("status") == "active" and not _is_expired(claim, current)
    ]
    superseded: set[str] = set()
    stack = [target for claim in live_seeds for target in claim.get("supersedes", [])]
    while stack:
        target_id = stack.pop()
        if target_id in superseded:
            continue
        superseded.add(target_id)
        target = claims.get(target_id)
        if target is not None:
            stack.extend(target.get("supersedes", []))
    active, historical = [], []
    for claim in sorted(claims.values(), key=lambda item: item["id"]):
        item = copy.deepcopy(claim)
        if item["status"] == "active" and item["id"] in superseded:
            item["effective_status"] = "superseded"
        else:
            item["effective_status"] = (
                "expired"
                if item["status"] == "active" and _is_expired(item, current)
                else item["status"]
            )
        (active if item["effective_status"] == "active" else historical).append(item)
    return {
        "active_claims": active,
        "historical_claims": historical,
        "as_of": current.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }


def semantic_diff(
    before: Iterable[Mapping[str, Any]],
    after: Iterable[Mapping[str, Any]],
    now: str | None = None,
) -> dict[str, Any]:
    left_view, right_view = (
        resolved_active_view(before, now),
        resolved_active_view(after, now),
    )
    left = {item["id"]: item for item in left_view["active_claims"]}
    right = {item["id"]: item for item in right_view["active_claims"]}
    added = [right[key] for key in sorted(right.keys() - left.keys())]
    removed = [left[key] for key in sorted(left.keys() - right.keys())]
    changed = []
    for key in sorted(left.keys() & right.keys()):
        if claim_fingerprint(left[key]) != claim_fingerprint(right[key]):
            changed.append({"before": left[key], "after": right[key]})
    before_all = {
        item["id"]: item
        for item in left_view["active_claims"] + left_view["historical_claims"]
    }
    after_all = {
        item["id"]: item
        for item in right_view["active_claims"] + right_view["historical_claims"]
    }
    lifecycle = [
        {
            "id": key,
            "before": before_all[key].get(
                "effective_status", before_all[key]["status"]
            ),
            "after": after_all[key].get("effective_status", after_all[key]["status"]),
        }
        for key in sorted(before_all.keys() & after_all.keys())
        if before_all[key].get("effective_status", before_all[key]["status"])
        != after_all[key].get("effective_status", after_all[key]["status"])
    ]
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "lifecycle": lifecycle,
    }


def plan_merge(
    local_revisions: Iterable[Mapping[str, Any]],
    remote_revisions: Iterable[Mapping[str, Any]],
    now: str | None = None,
) -> dict[str, Any]:
    """Return a merge plan. Divergent semantic keys always become durable conflicts."""
    local = resolved_active_view(local_revisions, now)["active_claims"]
    remote = resolved_active_view(remote_revisions, now)["active_claims"]
    by_key: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for side, claims in (("local", local), ("remote", remote)):
        for claim in claims:
            by_key.setdefault(claim["semantic_key"], {"local": [], "remote": []})[
                side
            ].append(claim)
    auto_claims, conflicts = [], []
    for key in sorted(by_key):
        sides = by_key[key]
        if not sides["local"] or not sides["remote"]:
            auto_claims.extend(copy.deepcopy(sides["local"] or sides["remote"]))
            continue
        local_fingerprints = {claim_fingerprint(claim) for claim in sides["local"]}
        remote_fingerprints = {claim_fingerprint(claim) for claim in sides["remote"]}
        if local_fingerprints == remote_fingerprints:
            auto_claims.extend(copy.deepcopy(sides["local"]))
            continue
        conflicts.append(
            {
                "id": "conflict-"
                + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16],
                "status": "unresolved",
                "semantic_key": key,
                "local_claims": copy.deepcopy(sides["local"]),
                "remote_claims": copy.deepcopy(sides["remote"]),
                "reason": "active claims for the same semantic key differ; no automatic winner is permitted",
            }
        )
    return {
        "auto_claims": sorted(auto_claims, key=lambda item: item["id"]),
        "conflicts": conflicts,
        "mergeable": not conflicts,
    }
