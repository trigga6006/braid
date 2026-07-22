"""Thin, strict A2A artifact adapter for signed Braid disclosures.

It owns no task, transport, inbox, signature policy, or context state.  A2A is
only the artifact envelope; the ledger remains the acceptance boundary.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from typing import Any

import context_model
from context_security import (
    SecurityError,
    digest as security_digest,
    verify_disclosure_grant,
    verify_export,
)


BUNDLE_SCHEMA = "context-disclosure/v1"
BUNDLE_MIME_TYPE = "application/vnd.braid.context-disclosure+json;version=1"
MAX_BUNDLE_BYTES = 1_000_000
MAX_CLAIMS = 500
_ARTIFACT_FIELDS = frozenset(
    {"artifactId", "name", "description", "parts", "metadata", "extensions"}
)
_PART_FIELDS = frozenset({"kind", "data", "metadata"})


class ContextAdapterError(ValueError):
    """Untrusted interchange data is not a valid portable Context Pack."""


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ContextAdapterError("Context Pack contains a non-JSON value.") from error


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict) and isinstance(to_dict(), Mapping):
        return dict(to_dict())
    raise ContextAdapterError(f"{label} must be a JSON object.")


def normalize_bundle(bundle: Any) -> dict[str, Any]:
    """Canonicalize and cryptographically verify one governed disclosure."""
    value = _mapping(bundle, "signed disclosure")
    encoded = canonical_json(value).encode("utf-8")
    if len(encoded) > MAX_BUNDLE_BYTES:
        raise ContextAdapterError(
            "Signed disclosure exceeds the portable interchange size limit."
        )
    normalized = json.loads(encoded)
    if (
        set(normalized) != {"format", "export", "grant"}
        or normalized.get("format") != BUNDLE_SCHEMA
    ):
        raise ContextAdapterError(
            f"Unsupported signed disclosure format: {normalized.get('format')!r}."
        )
    try:
        signed, grant = normalized["export"], normalized["grant"]
        verified = verify_export(signed)
        revision = verified.export["revision"]
        context_model.validate_revision(revision)
        if len(revision["claims"]) > MAX_CLAIMS:
            raise ContextAdapterError(
                "Signed disclosure claims exceed the interchange limit."
            )
        verify_disclosure_grant(
            grant,
            pack_digest=security_digest(revision),
            project=str(signed["project"]),
            scope=str(signed["scope"]),
            recipient=str(signed["recipient"]),
            policy_digest=str(signed["policy_digest"]),
            min_policy_version=int(signed["policy_version"]),
            expected_issuer_key_id=str(signed["author_key_id"]),
        )
        if grant.get("issuer_public_key") != signed.get("author_public_key"):
            raise ContextAdapterError(
                "Disclosure grant issuer does not match export author."
            )
    except (KeyError, TypeError, ValueError, SecurityError) as error:
        raise ContextAdapterError(f"Invalid signed disclosure: {error}") from error
    return normalized


def bundle_digest(bundle: Any) -> str:
    return hashlib.sha256(
        canonical_json(normalize_bundle(bundle)).encode("utf-8")
    ).hexdigest()


def bundle_to_a2a_artifact(bundle: Any) -> dict[str, Any]:
    """Encode one signed disclosure as an A2A v1-shaped data Artifact.

    Deliberately no task ID is created: the calling A2A implementation owns task
    lifecycle and may attach this artifact to an existing task/message.
    """
    normalized = normalize_bundle(bundle)
    revision = normalized["export"]["revision"]
    return {
        "artifactId": revision["id"],
        "name": "Braid governed context disclosure",
        "description": "Signed, recipient-scoped Context Pack disclosure and grant.",
        "parts": [
            {
                "kind": "data",
                "data": normalized,
                "metadata": {"mimeType": BUNDLE_MIME_TYPE},
            }
        ],
        "metadata": {
            "mimeType": BUNDLE_MIME_TYPE,
            "schema": BUNDLE_SCHEMA,
            "sha256": bundle_digest(normalized),
        },
    }


def a2a_artifact_to_bundle(artifact: Any) -> dict[str, Any]:
    """Strictly decode an A2A artifact; callers still apply ledger policy on import."""
    value = _mapping(artifact, "A2A artifact")
    unknown = set(value) - _ARTIFACT_FIELDS
    if unknown:
        raise ContextAdapterError(
            "Unsupported A2A artifact field(s): " + ", ".join(sorted(unknown))
        )
    if not isinstance(value.get("artifactId"), str) or not value["artifactId"]:
        raise ContextAdapterError("A2A artifact requires a non-empty artifactId.")
    if not isinstance(value.get("name"), str) or not value["name"]:
        raise ContextAdapterError("A2A artifact requires a non-empty string name.")
    if "description" in value and not isinstance(value["description"], str):
        raise ContextAdapterError("A2A artifact description must be a string.")
    if "extensions" in value and (
        not isinstance(value["extensions"], list)
        or not all(isinstance(item, str) and item for item in value["extensions"])
    ):
        raise ContextAdapterError("A2A artifact extensions must be strings.")
    if not isinstance(value.get("parts"), list) or len(value["parts"]) != 1:
        raise ContextAdapterError(
            "A Braid A2A artifact requires exactly one data part."
        )
    metadata = value.get("metadata")
    if (
        not isinstance(metadata, Mapping)
        or set(metadata) != {"mimeType", "schema", "sha256"}
        or metadata.get("mimeType") != BUNDLE_MIME_TYPE
        or metadata.get("schema") != BUNDLE_SCHEMA
    ):
        raise ContextAdapterError(
            "A2A artifact has an unsupported Braid MIME type or schema."
        )
    part = _mapping(value["parts"][0], "A2A artifact part")
    if (
        set(part) - _PART_FIELDS
        or part.get("kind") != "data"
        or not isinstance(part.get("metadata"), Mapping)
        or set(part["metadata"]) != {"mimeType"}
    ):
        raise ContextAdapterError(
            "A Braid A2A artifact part must be a data part with metadata."
        )
    if part["metadata"].get("mimeType") != BUNDLE_MIME_TYPE:
        raise ContextAdapterError(
            "A2A data part MIME type does not identify a Braid Context Pack."
        )
    bundle = normalize_bundle(part.get("data"))
    if bundle["export"]["revision"]["id"] != value["artifactId"]:
        raise ContextAdapterError(
            "A2A artifactId must exactly match the disclosed revision ID."
        )
    if metadata.get("sha256") != bundle_digest(bundle):
        raise ContextAdapterError(
            "A2A artifact digest does not match its Context Pack."
        )
    return bundle
