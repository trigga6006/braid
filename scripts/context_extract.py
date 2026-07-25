#!/usr/bin/env python3
"""Deterministically stage privacy-preserving context claim candidates.

This module deliberately performs no model calls and never treats imported text as
instructions.  It is the narrow boundary between an exported conversation (or a
human-curated Markdown packet) and the context ledger's typed claim model.
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
import unicodedata
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from typing import Any


CLAIM_KINDS = frozenset(
    (
        "fact",
        "status",
        "decision",
        "constraint",
        "hypothesis",
        "question",
        "action",
        "blocker",
    )
)
MAX_SOURCE_CHARS = 2_000_000
MAX_MESSAGES = 20_000
MAX_CANDIDATES = 500

_HEADING_KINDS = (
    ("blocker", "blocker"),
    ("risk", "blocker"),
    ("open question", "question"),
    ("question", "question"),
    ("decision", "decision"),
    ("constraint", "constraint"),
    ("rejected", "constraint"),
    ("hypoth", "hypothesis"),
    ("assumption", "hypothesis"),
    ("next step", "action"),
    ("action", "action"),
    ("todo", "action"),
    ("completed", "status"),
    ("implementation", "status"),
    ("status", "status"),
    ("fact", "fact"),
    ("confirmed", "fact"),
)

_CREDENTIAL_PATTERNS = (
    re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", re.I),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b", re.I
    ),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(
        r"\b(?:xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.)"
    ),
    re.compile(r"(?i)\b(?:authorization|proxy-authorization)\s*:\s*bearer\s+\S+"),
    re.compile(
        r"(?i)\b(?:password|passwd|api[_ -]?key|access[_ -]?token|secret)\s*[:=]\s*(?!(?:redacted|omitted|none|not[ -]?set)\b)\S{3,}"
    ),
    # Bounded scheme/user/password runs keep this linear (an unbounded
    # [a-z0-9+.-]* before "://" backtracks quadratically on input like "a.a.a").
    re.compile(r"(?i)\b[a-z][a-z0-9+.-]{0,31}://[^\s/@:]{1,512}:[^\s/@]{1,512}@"),
)
# Bounded local-part/domain lengths keep this linear instead of O(n^2) on a long
# run of "._%+-" with no "@".
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,255}\.[A-Z]{2,24}\b", re.I)
_PHONE = re.compile(
    r"(?<!\w)(?:\+?\d{1,3}[ .-]?)?(?:\(?\d{3}\)?[ .-]?)\d{3}[ .-]\d{4}(?!\w)"
)
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# Best-effort, deliberately over-broad instruction-shaped detector.  A hit only
# marks the source untrusted/tentative (fail-safe), so false positives are
# acceptable; all quantifiers are bounded so it cannot backtrack catastrophically.
_INJECTION = re.compile(
    r"(?i)"
    r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?"
    r"\b(?:previous|prior|above|earlier|preceding|all|the|these|those|your|any|system|initial)\b"
    r"[^.\n]{0,40}?"
    r"\b(?:instruction|instructions|rule|rules|prompt|prompts|direction|directions|guideline|guidelines)\b"
    r"|\b(?:ignore|disregard|forget)\s+(?:everything|all)\b"
    r"|\bfrom\s+now\s+on\b"
    r"|\b(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are)|"
    r"new\s+(?:instructions|rules|persona|system\s+prompt))\b"
    r"|\b(?:system|developer)\s+(?:message|prompt)\b"
    r"|\b(?:jailbreak|prompt\s+injection)\b"
)
_BULLET = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+|>\s?)")
_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$")
_SPACE = re.compile(r"\s+")
_LOW_SIGNAL = re.compile(
    r"(?i)^(?:ok(?:ay)?|yes|no|thanks?(?: you)?|got it|sounds good|looks good|acknowledged|"
    r"understood|cool|great|perfect|done|continue|go ahead|let me know)[.! ]*$"
)
_TOPIC_PREFIX = re.compile(
    r"(?i)^(?:(?:correction|decision|constraint|fact|status|update|action item|todo|blocker)\s*:\s*|branch\s+[a-z0-9_-]+\s*:\s*)+"
)


@dataclasses.dataclass(frozen=True)
class SourceReference:
    """A non-reversible locator; it intentionally excludes imported raw text."""

    event_index: int
    role: str
    timestamp: str
    event_sha256: str
    span_start: int
    span_end: int
    span_sha256: str

    def public(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class ClaimCandidate:
    candidate_id: str
    kind: str
    statement: str
    source: SourceReference
    confidence: str = "candidate"
    untrusted: bool = False
    redactions: tuple[str, ...] = ()

    def public(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "kind": self.kind,
            "statement": self.statement,
            "source": self.source.public(),
            "confidence": self.confidence,
            "untrusted": self.untrusted,
            "redactions": list(self.redactions),
        }


@dataclasses.dataclass(frozen=True)
class ExtractionNotice:
    event_index: int
    code: str
    event_sha256: str

    def public(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class ExtractionResult:
    candidates: tuple[ClaimCandidate, ...]
    notices: tuple[ExtractionNotice, ...]

    def public(self) -> dict[str, Any]:
        return {
            "candidates": [item.public() for item in self.candidates],
            "notices": [item.public() for item in self.notices],
        }


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical(value: str) -> str:
    return _SPACE.sub(" ", unicodedata.normalize("NFC", value).strip())


def _event_hash(role: str, timestamp: str, text: str) -> str:
    return _hash("\x1f".join((role, timestamp, unicodedata.normalize("NFC", text))))


def _contains_credential(text: str) -> bool:
    return any(pattern.search(text) for pattern in _CREDENTIAL_PATTERNS)


def _redact_pii(text: str) -> tuple[str, tuple[str, ...]]:
    labels: list[str] = []
    for pattern, label, replacement in (
        (_EMAIL, "email", "[redacted-email]"),
        (_PHONE, "phone", "[redacted-phone]"),
        (_SSN, "ssn", "[redacted-ssn]"),
    ):
        if pattern.search(text):
            labels.append(label)
            text = pattern.sub(replacement, text)
    return text, tuple(labels)


def _heading_kind(heading: str) -> str | None:
    lowered = heading.casefold()
    for marker, kind in _HEADING_KINDS:
        if marker in lowered:
            return kind
    return None


def classify(statement: str, section_kind: str | None = None) -> str:
    """Classify using explicit text rules; section labels take precedence."""
    if section_kind in CLAIM_KINDS:
        return section_kind
    lower = statement.casefold()
    if statement.rstrip().endswith("?") or re.match(
        r"^(?:who|what|when|where|why|how|can|should|is|are)\b", lower
    ):
        return "question"
    if re.search(
        r"\b(?:block(?:ed|er)?|risk|failure|failing|regression|incident)\b", lower
    ):
        return "blocker"
    if re.search(r"\b(?:decided|decision|choose|chosen|approved|will use)\b", lower):
        return "decision"
    if re.search(
        r"\b(?:must|cannot|can't|requires?|only supports?|not supported|constraint)\b",
        lower,
    ):
        return "constraint"
    if re.search(
        r"\b(?:hypothesis|assum(?:e|ption)|might|likely|suspect|uncertain|perhaps)\b",
        lower,
    ):
        return "hypothesis"
    if re.search(
        r"\b(?:next step|todo|to-do|action item|follow up|implement|investigate|verify)\b",
        lower,
    ):
        return "action"
    if re.search(
        r"\b(?:done|complete[ds]?|implemented|passing|deployed|in progress|status)\b",
        lower,
    ):
        return "status"
    return "fact"


def _markdown_spans(text: str) -> Iterable[tuple[int, int, str, str | None]]:
    """Yield meaningful Markdown lines with their active semantic heading."""
    active_kind: str | None = None
    offset = 0
    for line in text.splitlines(keepends=True):
        raw = line.rstrip("\r\n")
        heading = _HEADING.match(raw)
        if heading:
            active_kind = _heading_kind(heading.group(1))
        else:
            cleaned = _BULLET.sub("", raw).strip()
            # A paragraph is valid too; ignore quote/code separators and blank lines.
            if (
                cleaned
                and not cleaned.startswith("```")
                and not re.fullmatch(r"[-*_]{3,}", cleaned)
            ):
                start = offset + raw.find(cleaned)
                yield start, start + len(cleaned), cleaned, active_kind
        offset += len(line)


def _stage_event(
    event_index: int, role: str, timestamp: str, text: str, markdown: bool
) -> tuple[list[ClaimCandidate], list[ExtractionNotice]]:
    event_sha = _event_hash(role, timestamp, text)
    if _contains_credential(text):
        return [], [
            ExtractionNotice(event_index, "blocked_sensitive_credential", event_sha)
        ]
    untrusted = bool(_INJECTION.search(text))
    notices = (
        [ExtractionNotice(event_index, "untrusted_prompt_injection", event_sha)]
        if untrusted
        else []
    )
    spans = (
        _markdown_spans(text)
        if markdown
        else (
            (match.start(), match.end(), match.group(), None)
            for match in re.finditer(r"[^\r\n]+", text)
        )
    )
    candidates: list[ClaimCandidate] = []
    for start, end, raw_statement, section_kind in spans:
        # Prompt injection language remains auditable only as an untrusted source; never create an action from it.
        if _INJECTION.search(raw_statement):
            continue
        statement, redactions = _redact_pii(_canonical(raw_statement))
        if not statement or _LOW_SIGNAL.fullmatch(statement) or len(statement) < 4:
            continue
        kind = classify(statement, section_kind)
        source = SourceReference(
            event_index, role, timestamp, event_sha, start, end, _hash(raw_statement)
        )
        candidate_id = _hash(
            "\x1f".join((kind, statement, event_sha, str(start), str(end)))
        )[:24]
        candidates.append(
            ClaimCandidate(
                candidate_id,
                kind,
                statement,
                source,
                untrusted=untrusted,
                redactions=redactions,
            )
        )
        if len(candidates) > MAX_CANDIDATES:
            raise ValueError(
                f"Source produces more than {MAX_CANDIDATES} reviewable claims; "
                "split it into smaller scoped packets."
            )
    return candidates, notices


def extract_markdown(
    markdown: str, *, role: str = "curated", timestamp: str = ""
) -> ExtractionResult:
    """Extract staged candidates from an explicitly curated Markdown context packet."""
    if not isinstance(markdown, str):
        raise TypeError("markdown must be a string")
    if len(markdown) > MAX_SOURCE_CHARS:
        raise ValueError(
            f"Markdown exceeds the {MAX_SOURCE_CHARS}-character extraction limit."
        )
    candidates, notices = _stage_event(0, role, timestamp, markdown, markdown=True)
    return ExtractionResult(tuple(candidates), tuple(notices))


def extract_messages(messages: Sequence[Any]) -> ExtractionResult:
    """Extract staged candidates from ``braid_session.Message``-compatible values.

    Only ``role``, ``text``, and optional ``timestamp`` are read.  The resulting
    source references contain hashes and offsets, never the original event text.
    """
    if len(messages) > MAX_MESSAGES:
        raise ValueError(
            f"Session exceeds the {MAX_MESSAGES}-message extraction limit."
        )
    candidates: list[ClaimCandidate] = []
    notices: list[ExtractionNotice] = []
    source_chars = 0
    for index, message in enumerate(messages):
        text = getattr(message, "text", None)
        if not isinstance(text, str):
            raise TypeError(f"messages[{index}].text must be a string")
        source_chars += len(text)
        if source_chars > MAX_SOURCE_CHARS:
            raise ValueError(
                f"Session exceeds the {MAX_SOURCE_CHARS}-character extraction limit."
            )
        role = str(getattr(message, "role", ""))
        timestamp = str(getattr(message, "timestamp", ""))
        staged, event_notices = _stage_event(
            index, role, timestamp, text, markdown=False
        )
        candidates.extend(staged)
        if len(candidates) > MAX_CANDIDATES:
            raise ValueError(
                f"Session produces more than {MAX_CANDIDATES} reviewable claims; "
                "extract a smaller task scope."
            )
        notices.extend(event_notices)
    # Repeated acknowledgements or copied status lines should not inflate a
    # context pack. Keep the first source-backed occurrence deterministically.
    unique: dict[tuple[str, str], ClaimCandidate] = {}
    for candidate in candidates:
        unique.setdefault((candidate.kind, candidate.statement.casefold()), candidate)
    return ExtractionResult(tuple(unique.values()), tuple(notices))


def _rfc3339_or_epoch(value: str) -> str:
    """Normalize a source time without making extraction depend on wall-clock time."""
    if not value:
        return "1970-01-01T00:00:00Z"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return "1970-01-01T00:00:00Z"
    if parsed.tzinfo is None:
        return "1970-01-01T00:00:00Z"
    return (
        parsed.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _semantic_key(candidate: ClaimCandidate) -> str:
    """Return a conservative topic key for diff/conflict grouping.

    It removes explicit lifecycle/branch prefixes and values after a copula.
    Ambiguous keys remain reviewable; the extractor does not auto-resolve them.
    """
    text = _TOPIC_PREFIX.sub("", candidate.statement).split(";", 1)[0]
    text = re.split(
        r"(?i)\s+(?:is|are|was|were|will be|must be|equals?)\s+", text, maxsplit=1
    )[0]
    words = re.findall(r"[a-z][a-z0-9_-]*", text.casefold())[:10]
    topic = "-".join(words).strip("-")
    return (topic or f"source-{candidate.source.span_sha256[:24]}")[:128]


def to_context_claims(result: ExtractionResult) -> list[dict[str, Any]]:
    """Convert staged candidates to validated ``context_model`` claims.

    ``status`` is represented as a fact tagged ``status`` because the portable
    model deliberately has no status claim kind.  Prompt-injection-shaped input
    remains explicitly marked untrusted and tentative.  This function imports
    the model only at the integration boundary, so the extraction core remains
    standard-library-only and independently testable.
    """
    from context_model import make_claim, validate_claim

    claims: list[dict[str, Any]] = []
    for candidate in result.candidates:
        observed_at = _rfc3339_or_epoch(candidate.source.timestamp)
        kind = "fact" if candidate.kind == "status" else candidate.kind
        labels = list(candidate.redactions)
        if candidate.kind == "status":
            labels.append("status")
        if candidate.untrusted:
            labels.append("untrusted-source")
        provenance = [
            {
                "type": "transcript_excerpt",
                "uri": f"session://redacted/events/{candidate.source.event_index}-{candidate.source.event_sha256[:16]}#{candidate.source.span_start}-{candidate.source.span_end}",
                "digest": "sha256:" + candidate.source.span_sha256,
                "observed_at": observed_at,
            }
        ]
        claim_id = "claim-" + _hash(kind + "\x1f" + candidate.statement.casefold())[:24]
        claim = make_claim(
            claim_id,
            kind,
            candidate.statement,
            _semantic_key(candidate),
            provenance,
            confidence="tentative" if candidate.untrusted else "likely",
            observed_at=observed_at,
            labels=labels,
        )
        claim["redactions"] = list(candidate.redactions)
        validate_claim(claim)
        claims.append(claim)
    by_key: dict[str, list[dict[str, Any]]] = {}
    for claim in claims:
        prior = by_key.setdefault(claim["semantic_key"], [])
        if re.search(
            r"(?i)\b(?:correction|supersed(?:e|ed|ing)|replaces?)\b", claim["statement"]
        ):
            claim["supersedes"] = [item["id"] for item in prior]
            validate_claim(claim)
        prior.append(claim)
    return claims


def extract_markdown_claims(
    markdown: str, *, role: str = "curated", timestamp: str = ""
) -> list[dict[str, Any]]:
    """Convenience integration API for a curated packet and Context Pack v0.1."""
    return to_context_claims(extract_markdown(markdown, role=role, timestamp=timestamp))


def extract_message_claims(messages: Sequence[Any]) -> list[dict[str, Any]]:
    """Convenience integration API for braid_session messages and Context Pack v0.1."""
    return to_context_claims(extract_messages(messages))
