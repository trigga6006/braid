"""Signed Context Pull Requests for sovereign agent-to-agent collaboration.

The exchange objects in this module are application payloads, not transport
messages and not instructions.  They can ride Team Hub, A2A, MCP, SLIM, or a
file without granting the sender authority over the receiving agent.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import time
from typing import Any, Mapping

from context_model import CLAIM_KINDS, SENSITIVITY
from context_security import (
    AuthorIdentity,
    SecurityError,
    canonical_bytes,
    create_identity_assertion,
    identity_principal,
    scan_sensitive,
    verify_identity_assertion,
)


REQUEST_FORMAT = "context-pull-request/v1"
RESPONSE_FORMAT = "context-pull-response/v1"
REQUEST_ACTION = "context-pull-request"
RESPONSE_ACTION = "context-pull-response"
MAX_QUESTION_CHARS = 4_000
MAX_PURPOSE_CHARS = 500
MAX_NOTE_CHARS = 1_000
MAX_SELECTOR_ITEMS = 64
MAX_REQUEST_CLAIMS = 100
MAX_REQUEST_BYTES = 900_000
MAX_LIFETIME_SECONDS = 31 * 24 * 3600
RESPONSE_STATUSES = frozenset(
    {"fulfilled", "no-change", "declined", "needs-clarification"}
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_SEMANTIC_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_PRINCIPAL = re.compile(r"^ed25519:[0-9a-f]{64}$")


class ContextExchangeError(ValueError):
    """A pull request or response violates the exchange contract."""


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ContextExchangeError(f"{label} is invalid.")
    return value


def _principal(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _PRINCIPAL.fullmatch(value):
        raise ContextExchangeError(f"{label} is invalid.")
    return value


def _text(value: Any, label: str, maximum: int, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value:
        raise ContextExchangeError(f"{label} is invalid.")
    normalized = value.strip()
    if not allow_empty and not normalized:
        raise ContextExchangeError(f"{label} is required.")
    return normalized


def _positive_int(value: Any, label: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > maximum
    ):
        raise ContextExchangeError(f"{label} is invalid.")
    return value


def _selector_list(
    value: Any, label: str, *, allowed: frozenset[str] | None = None
) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > MAX_SELECTOR_ITEMS
        or not all(isinstance(item, str) for item in value)
    ):
        raise ContextExchangeError(f"{label} is invalid.")
    normalized: list[str] = []
    for item in value:
        item = item.strip()
        if (
            not item
            or len(item) > 128
            or "\x00" in item
            or (allowed is not None and item not in allowed)
        ):
            raise ContextExchangeError(f"{label} is invalid.")
        normalized.append(item)
    if len(set(normalized)) != len(normalized):
        raise ContextExchangeError(f"{label} contains duplicates.")
    return sorted(normalized)


def _timing(
    created_at: Any,
    expires_at: Any,
    *,
    now: int | None = None,
    allow_expired: bool = False,
) -> tuple[int, int]:
    current = int(time.time()) if now is None else now
    created = _positive_int(created_at, "creation time", 2**63 - 1)
    expires = _positive_int(expires_at, "expiry", 2**63 - 1)
    if created > current + 300 or expires <= created:
        raise ContextExchangeError("Exchange timing is invalid.")
    if expires > created + MAX_LIFETIME_SECONDS or (
        expires <= current and not allow_expired
    ):
        raise ContextExchangeError("Exchange is expired or exceeds the lifetime limit.")
    return created, expires


def _request_subject(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "action": REQUEST_ACTION,
        "format": value["format"],
        "request_id": value["request_id"],
        "project_id": value["project_id"],
        "sender": value["sender"],
        "recipient": value["recipient"],
        "purpose": value["purpose"],
        "question": value["question"],
        "selectors": value["selectors"],
        "since_revision": value["since_revision"],
        "max_sensitivity": value["max_sensitivity"],
        "max_claims": value["max_claims"],
        "max_bytes": value["max_bytes"],
        "created_at": value["created_at"],
        "expires_at": value["expires_at"],
    }


def create_request(
    identity: AuthorIdentity,
    *,
    project_id: str,
    recipient: str,
    purpose: str,
    question: str,
    kinds: list[str] | None = None,
    semantic_keys: list[str] | None = None,
    labels: list[str] | None = None,
    since_revision: str | None = None,
    max_sensitivity: str = "internal",
    max_claims: int = 50,
    max_bytes: int = 250_000,
    ttl_seconds: int = 7 * 24 * 3600,
    now: int | None = None,
) -> dict[str, Any]:
    """Create a signed, recipient-bound request for a minimal semantic change."""
    current = int(time.time()) if now is None else now
    if ttl_seconds < 1 or ttl_seconds > MAX_LIFETIME_SECONDS:
        raise ContextExchangeError("Request lifetime is invalid.")
    request: dict[str, Any] = {
        "format": REQUEST_FORMAT,
        "request_id": "creq_" + secrets.token_hex(16),
        "project_id": _identifier(project_id, "project ID"),
        "sender": identity_principal(identity),
        "recipient": _principal(recipient, "request recipient"),
        "purpose": _text(purpose, "request purpose", MAX_PURPOSE_CHARS),
        "question": _text(question, "request question", MAX_QUESTION_CHARS),
        "selectors": {
            "kinds": _selector_list(kinds or [], "request kinds", allowed=CLAIM_KINDS),
            "semantic_keys": _selector_list(
                semantic_keys or [], "request semantic keys"
            ),
            "labels": _selector_list(labels or [], "request labels"),
        },
        "since_revision": (
            _identifier(since_revision, "since revision")
            if since_revision is not None
            else None
        ),
        "max_sensitivity": max_sensitivity,
        "max_claims": _positive_int(max_claims, "maximum claims", MAX_REQUEST_CLAIMS),
        "max_bytes": _positive_int(max_bytes, "maximum bytes", MAX_REQUEST_BYTES),
        "created_at": current,
        "expires_at": current + ttl_seconds,
    }
    if max_sensitivity not in SENSITIVITY:
        raise ContextExchangeError("Request sensitivity is invalid.")
    if scan_sensitive({"purpose": request["purpose"], "question": request["question"]}):
        raise ContextExchangeError(
            "Context Pull Request contains credential-like material; redact it first."
        )
    request["assertion"] = create_identity_assertion(
        identity, _request_subject(request)
    )
    return verify_request(request, now=current)


def verify_request(
    value: Mapping[str, Any],
    *,
    expected_project: str | None = None,
    expected_recipient: str | None = None,
    now: int | None = None,
    allow_expired: bool = False,
) -> dict[str, Any]:
    """Strictly validate and authenticate a Context Pull Request."""
    required = {
        "format",
        "request_id",
        "project_id",
        "sender",
        "recipient",
        "purpose",
        "question",
        "selectors",
        "since_revision",
        "max_sensitivity",
        "max_claims",
        "max_bytes",
        "created_at",
        "expires_at",
        "assertion",
    }
    request = dict(value)
    if set(request) != required or request.get("format") != REQUEST_FORMAT:
        raise ContextExchangeError("Context Pull Request shape is invalid.")
    request["request_id"] = _identifier(request["request_id"], "request ID")
    request["project_id"] = _identifier(request["project_id"], "project ID")
    request["sender"] = _principal(request["sender"], "request sender")
    request["recipient"] = _principal(request["recipient"], "request recipient")
    request["purpose"] = _text(request["purpose"], "request purpose", MAX_PURPOSE_CHARS)
    request["question"] = _text(
        request["question"], "request question", MAX_QUESTION_CHARS
    )
    selectors = request["selectors"]
    if not isinstance(selectors, Mapping) or set(selectors) != {
        "kinds",
        "semantic_keys",
        "labels",
    }:
        raise ContextExchangeError("Request selectors are invalid.")
    request["selectors"] = {
        "kinds": _selector_list(
            selectors["kinds"], "request kinds", allowed=CLAIM_KINDS
        ),
        "semantic_keys": _selector_list(
            selectors["semantic_keys"], "request semantic keys"
        ),
        "labels": _selector_list(selectors["labels"], "request labels"),
    }
    for semantic_key in request["selectors"]["semantic_keys"]:
        if not _SEMANTIC_KEY.fullmatch(semantic_key):
            raise ContextExchangeError("Request semantic key is invalid.")
    since = request["since_revision"]
    if since is not None:
        request["since_revision"] = _identifier(since, "since revision")
    if request["max_sensitivity"] not in SENSITIVITY:
        raise ContextExchangeError("Request sensitivity is invalid.")
    request["max_claims"] = _positive_int(
        request["max_claims"], "maximum claims", MAX_REQUEST_CLAIMS
    )
    request["max_bytes"] = _positive_int(
        request["max_bytes"], "maximum bytes", MAX_REQUEST_BYTES
    )
    request["created_at"], request["expires_at"] = _timing(
        request["created_at"],
        request["expires_at"],
        now=now,
        allow_expired=allow_expired,
    )
    if expected_project is not None and request["project_id"] != expected_project:
        raise ContextExchangeError("Context Pull Request is for another project.")
    if expected_recipient is not None and request["recipient"] != expected_recipient:
        raise ContextExchangeError("Context Pull Request is for another endpoint.")
    if scan_sensitive({"purpose": request["purpose"], "question": request["question"]}):
        raise ContextExchangeError(
            "Context Pull Request contains credential-like material."
        )
    assertion = request["assertion"]
    if not isinstance(assertion, Mapping):
        raise ContextExchangeError("Context Pull Request signature is invalid.")
    try:
        signer = verify_identity_assertion(assertion, _request_subject(request))
    except SecurityError as error:
        raise ContextExchangeError(
            "Context Pull Request signature is invalid."
        ) from error
    if signer != request["sender"]:
        raise ContextExchangeError("Context Pull Request signer does not match sender.")
    request["assertion"] = dict(assertion)
    return request


def _response_subject(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "action": RESPONSE_ACTION,
        "format": value["format"],
        "response_id": value["response_id"],
        "request_id": value["request_id"],
        "request_sha256": value["request_sha256"],
        "project_id": value["project_id"],
        "sender": value["sender"],
        "recipient": value["recipient"],
        "status": value["status"],
        "note": value["note"],
        "bundle_sha256": value["bundle_sha256"],
        "created_at": value["created_at"],
        "expires_at": value["expires_at"],
    }


def create_response(
    identity: AuthorIdentity,
    request: Mapping[str, Any],
    *,
    status: str,
    bundle: Mapping[str, Any] | None = None,
    note: str = "",
    now: int | None = None,
) -> dict[str, Any]:
    """Create a signed terminal response correlated to an authenticated request."""
    verified_request = verify_request(request, now=now)
    sender = identity_principal(identity)
    if sender != verified_request["recipient"]:
        raise ContextExchangeError("Only the request recipient can respond.")
    if status not in RESPONSE_STATUSES:
        raise ContextExchangeError("Context Pull Response status is invalid.")
    if status == "fulfilled" and not isinstance(bundle, Mapping):
        raise ContextExchangeError("A fulfilled response requires a Context Pack.")
    if status != "fulfilled" and bundle is not None:
        raise ContextExchangeError(
            "Only a fulfilled response may contain a Context Pack."
        )
    normalized_note = _text(note, "response note", MAX_NOTE_CHARS, allow_empty=True)
    if scan_sensitive({"note": normalized_note}):
        raise ContextExchangeError("Response note contains credential-like material.")
    current = int(time.time()) if now is None else now
    response_expiry = min(
        int(verified_request["expires_at"]), current + MAX_LIFETIME_SECONDS
    )
    if response_expiry <= current:
        raise ContextExchangeError("Context Pull Request has expired.")
    normalized_bundle = dict(bundle) if bundle is not None else None
    bundle_sha256 = (
        hashlib.sha256(canonical_bytes(normalized_bundle)).hexdigest()
        if normalized_bundle is not None
        else None
    )
    response: dict[str, Any] = {
        "format": RESPONSE_FORMAT,
        "response_id": "cresp_" + secrets.token_hex(16),
        "request_id": verified_request["request_id"],
        "request_sha256": exchange_digest(verified_request),
        "project_id": verified_request["project_id"],
        "sender": sender,
        "recipient": verified_request["sender"],
        "status": status,
        "note": normalized_note,
        "bundle_sha256": bundle_sha256,
        "bundle": normalized_bundle,
        "created_at": current,
        "expires_at": response_expiry,
    }
    response["assertion"] = create_identity_assertion(
        identity, _response_subject(response)
    )
    return verify_response(response, request=verified_request, now=current)


def verify_response(
    value: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
    expected_project: str | None = None,
    expected_recipient: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Validate a response and bind it to the exact locally recorded request."""
    required = {
        "format",
        "response_id",
        "request_id",
        "request_sha256",
        "project_id",
        "sender",
        "recipient",
        "status",
        "note",
        "bundle_sha256",
        "bundle",
        "created_at",
        "expires_at",
        "assertion",
    }
    response = dict(value)
    if set(response) != required or response.get("format") != RESPONSE_FORMAT:
        raise ContextExchangeError("Context Pull Response shape is invalid.")
    verified_request = verify_request(request, now=now)
    response["response_id"] = _identifier(response["response_id"], "response ID")
    response["request_id"] = _identifier(response["request_id"], "request ID")
    if not isinstance(response["request_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", response["request_sha256"]
    ):
        raise ContextExchangeError("Context Pull Response request digest is invalid.")
    response["project_id"] = _identifier(response["project_id"], "project ID")
    response["sender"] = _principal(response["sender"], "response sender")
    response["recipient"] = _principal(response["recipient"], "response recipient")
    if (
        response["request_id"] != verified_request["request_id"]
        or not secrets.compare_digest(
            response["request_sha256"], exchange_digest(verified_request)
        )
        or response["project_id"] != verified_request["project_id"]
        or response["sender"] != verified_request["recipient"]
        or response["recipient"] != verified_request["sender"]
    ):
        raise ContextExchangeError("Context Pull Response does not match its request.")
    if expected_project is not None and response["project_id"] != expected_project:
        raise ContextExchangeError("Context Pull Response is for another project.")
    if expected_recipient is not None and response["recipient"] != expected_recipient:
        raise ContextExchangeError("Context Pull Response is for another endpoint.")
    if response["status"] not in RESPONSE_STATUSES:
        raise ContextExchangeError("Context Pull Response status is invalid.")
    response["note"] = _text(
        response["note"], "response note", MAX_NOTE_CHARS, allow_empty=True
    )
    if scan_sensitive({"note": response["note"]}):
        raise ContextExchangeError("Response note contains credential-like material.")
    response["created_at"], response["expires_at"] = _timing(
        response["created_at"], response["expires_at"], now=now
    )
    if (
        response["created_at"] < verified_request["created_at"]
        or response["expires_at"] > verified_request["expires_at"]
    ):
        raise ContextExchangeError(
            "Context Pull Response timing exceeds its request window."
        )
    bundle = response["bundle"]
    bundle_sha256 = response["bundle_sha256"]
    if response["status"] == "fulfilled":
        if not isinstance(bundle, Mapping) or not isinstance(bundle_sha256, str):
            raise ContextExchangeError("Fulfilled response Context Pack is missing.")
        actual = hashlib.sha256(canonical_bytes(bundle)).hexdigest()
        if not secrets.compare_digest(actual, bundle_sha256):
            raise ContextExchangeError("Response Context Pack digest does not match.")
        response["bundle"] = dict(bundle)
    elif bundle is not None or bundle_sha256 is not None:
        raise ContextExchangeError("Non-fulfilled response contains a Context Pack.")
    assertion = response["assertion"]
    if not isinstance(assertion, Mapping):
        raise ContextExchangeError("Context Pull Response signature is invalid.")
    try:
        signer = verify_identity_assertion(assertion, _response_subject(response))
    except SecurityError as error:
        raise ContextExchangeError(
            "Context Pull Response signature is invalid."
        ) from error
    if signer != response["sender"]:
        raise ContextExchangeError(
            "Context Pull Response signer does not match sender."
        )
    response["assertion"] = dict(assertion)
    return response


def exchange_digest(value: Mapping[str, Any]) -> str:
    """Return a stable digest for duplicate-safe local exchange persistence."""
    return hashlib.sha256(canonical_bytes(dict(value))).hexdigest()
