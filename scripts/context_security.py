"""Security boundary for immutable, multi-principal context exchange.

This module deliberately treats every received object as *quarantined data*.
Verification here authenticates an export and its disclosure grant; it never
authorizes tool use, file writes, or an automatic merge.  A caller must perform
its own explicit local promotion/merge decision after ``verify_export``.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import json
import os
import re
import secrets
import time
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


FORMAT = "braid-context-security/v1"
MAX_DEPTH = 24
# Large enough for any context_model-valid revision (MAX_CLAIMS=500 with rich
# provenance stays under MAX_REVISION_BYTES=1 MB, ~30-40k nodes), while still
# bounding an adversarial 2 MB import to a fast O(n) structural walk.
MAX_NODES = 100_000
MAX_STRING = 250_000
# Bounded, revocation-independent maximum lifetime for signed exports and grants.
MAX_LIFETIME_SECONDS = 31 * 24 * 3600
MAX_COLLECTION = 5_000
MAX_SIGNATURE = 128
HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")

EXPORT_FIELDS = frozenset(
    {
        "format",
        "revision",
        "project",
        "scope",
        "recipient",
        "policy_digest",
        "policy_version",
        "created_at",
        "expires_at",
        "parents",
        "author_key_id",
        "author_public_key",
        "signature",
    }
)
GRANT_FIELDS = frozenset(
    {
        "format",
        "kind",
        "grant_id",
        "pack_digest",
        "project",
        "scope",
        "recipient",
        "operations",
        "policy_digest",
        "policy_version",
        "issued_at",
        "expires_at",
        "delegable",
        "issuer_key_id",
        "issuer_public_key",
        "signature",
    }
)
SENSITIVE_PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github-token", re.compile(r"\bgh[opusr]_[A-Za-z0-9_]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("bearer-token", re.compile(r"\bbearer\s+[A-Za-z0-9._~+/-]{16,}\b", re.IGNORECASE)),
    (
        "credential-assignment",
        re.compile(
            r"\b(?:password|passwd|api[_ -]?key|access[_ -]?token|secret)"
            r"\s*[:=]\s*(?!(?:redacted|omitted|none|not[ -]?set)\b)\S{3,}",
            re.IGNORECASE,
        ),
    ),
    (
        "credential-url",
        # Bounded scheme/user/password runs keep this strictly linear; an
        # unbounded [a-z0-9+.-]* before "://" backtracks quadratically on input
        # like "a.a.a...".
        re.compile(
            r"\b[a-z][a-z0-9+.-]{0,31}://[^\s/@:]{1,512}:[^\s/@]{1,512}@",
            re.IGNORECASE,
        ),
    ),
)


class SecurityError(ValueError):
    """Input violates a security invariant; callers must fail closed."""


@dataclass(frozen=True)
class AuthorIdentity:
    key_id: str
    public_key: bytes
    _private_key: bytes


@dataclass(frozen=True)
class QuarantinedExport:
    """A verified export which still has no authority to perform an action."""

    export: Mapping[str, Any]
    digest: str
    author_key_id: str


_IDENTITY_THREAD_LOCK = threading.RLock()


@contextlib.contextmanager
def _identity_file_lock(target: Path) -> Iterable[None]:
    """Serialize identity bootstrap across threads and independent processes."""
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.with_name(target.name + ".lock")
    with _IDENTITY_THREAD_LOCK:
        handle = open(lock_path, "a+b")
        locked = False
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    handle.seek(0)
                    handle.write(b"0")
                    handle.flush()
                while True:
                    try:
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                        locked = True
                        break
                    except OSError:
                        time.sleep(0.02)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                locked = True
            yield
        finally:
            try:
                if os.name == "nt" and locked:
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                elif locked:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()


def _crypto() -> tuple[Any, Any, Any, Any]:
    """Use the bridge's pinned cryptography copy before importing crypto types.

    Importing a system cryptography package first would poison ``sys.modules``
    and prevent Network Bridge from selecting its pinned security dependency.
    """
    import network_bridge

    network_bridge.crypto_imports()
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    return serialization, Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64d(value: Any, maximum: int = 4096) -> bytes:
    if not isinstance(value, str) or len(value) > maximum * 2:
        raise SecurityError("invalid base64 value")
    try:
        result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as error:
        raise SecurityError("invalid base64 value") from error
    if len(result) > maximum:
        raise SecurityError("base64 value exceeds limit")
    # Reject non-canonical encodings (unused trailing bits, stray padding) so a
    # signed object has exactly one byte-for-byte encoding.  This keeps digests
    # that include a signature string stable and blocks signature malleability.
    if _b64e(result) != value:
        raise SecurityError("non-canonical base64 value")
    return result


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    """Canonical JSON used for content addressing and detached signatures."""
    validate_json_value(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _without_signature(value: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result.pop("signature", None)
    return result


def _private(identity: AuthorIdentity) -> Any:
    if len(identity._private_key) != 32:
        raise SecurityError("identity private key is invalid")
    _, Ed25519PrivateKey, _, _ = _crypto()
    return Ed25519PrivateKey.from_private_bytes(identity._private_key)


def _public(raw: bytes) -> Any:
    if len(raw) != 32:
        raise SecurityError("public key is invalid")
    _, _, Ed25519PublicKey, _ = _crypto()
    return Ed25519PublicKey.from_public_bytes(raw)


def identity_principal(identity: AuthorIdentity) -> str:
    """Return the only recipient principal this private identity may claim."""
    return "ed25519:" + identity.key_id


def create_identity_assertion(
    identity: AuthorIdentity, subject: Mapping[str, Any]
) -> dict[str, Any]:
    """Prove possession of a persistent recipient key for one handshake subject."""
    validate_json_value(subject)
    assertion: dict[str, Any] = {
        "format": "recipient-identity/v1",
        "key_id": identity.key_id,
        "public_key": _b64e(identity.public_key),
        "subject": dict(subject),
    }
    assertion["signature"] = _b64e(_private(identity).sign(canonical_bytes(assertion)))
    return assertion


def verify_identity_assertion(
    assertion: Mapping[str, Any], expected_subject: Mapping[str, Any]
) -> str:
    """Verify an exact handshake subject and return its key-derived principal."""
    if set(assertion) != {"format", "key_id", "public_key", "subject", "signature"}:
        raise SecurityError("identity assertion has unknown or missing fields")
    if assertion.get("format") != "recipient-identity/v1":
        raise SecurityError("unsupported identity assertion")
    subject = assertion.get("subject")
    if not isinstance(subject, Mapping) or canonical_bytes(subject) != canonical_bytes(
        expected_subject
    ):
        raise SecurityError("identity assertion subject mismatch")
    public = _b64d(assertion.get("public_key"), 64)
    key_id = assertion.get("key_id")
    if not isinstance(key_id, str) or hashlib.sha256(public).hexdigest() != key_id:
        raise SecurityError("identity assertion key mismatch")
    body = dict(assertion)
    signature = _b64d(body.pop("signature"), MAX_SIGNATURE)
    try:
        _public(public).verify(signature, canonical_bytes(body))
    except _crypto()[3] as error:
        raise SecurityError("identity assertion signature failed") from error
    return "ed25519:" + key_id


def _bridge_protect(value: bytes) -> dict[str, str]:
    # Import lazily so this module can be safely used by future bridge modules.
    import network_bridge

    return network_bridge.protect_secret(value)


def _bridge_unprotect(value: Mapping[str, Any]) -> bytes:
    import network_bridge

    return network_bridge.unprotect_secret(dict(value))


def load_or_create_identity(path: str | Path) -> AuthorIdentity:
    """Persist an Ed25519 identity with the existing OS-backed secret wrapper."""
    target = Path(path).expanduser()
    with _identity_file_lock(target):
        return _load_or_create_identity_unlocked(target)


def _load_or_create_identity_unlocked(target: Path) -> AuthorIdentity:
    if target.exists():
        try:
            stored = json.loads(target.read_text(encoding="utf-8"))
            public = _b64d(stored["public_key"], 64)
            private = _bridge_unprotect(stored["private_key"])
            key_id = str(stored["key_id"])
        except (
            OSError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
            SecurityError,
            SystemExit,
        ) as error:
            raise SecurityError(
                "identity file is invalid or cannot be unlocked"
            ) from error
        calculated = hashlib.sha256(public).hexdigest()
        if key_id != calculated or len(private) != 32:
            raise SecurityError("identity key identifier does not match its key")
        serialization, _, _, _ = _crypto()
        if (
            _private(AuthorIdentity(key_id, public, private))
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            != public
        ):
            raise SecurityError("identity public/private keys do not match")
        return AuthorIdentity(key_id, public, private)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        target.parent.chmod(0o700)
    except OSError:
        pass
    serialization, Ed25519PrivateKey, _, _ = _crypto()
    private_key = Ed25519PrivateKey.generate()
    private = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    identity = AuthorIdentity(hashlib.sha256(public).hexdigest(), public, private)
    body = {
        "format": FORMAT,
        "key_id": identity.key_id,
        "public_key": _b64e(public),
        "private_key": _bridge_protect(private),
    }
    temporary = target.with_name(
        f".{target.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    try:
        with open(temporary, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return identity


def _check_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise SecurityError(f"invalid {field}")
    return value


def _check_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HEX_DIGEST.fullmatch(value):
        raise SecurityError(f"invalid {field}")
    return value


def _check_time(value: Any, field: str, now: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SecurityError(f"invalid {field}")
    if now is not None and value > now + 300:
        raise SecurityError(f"{field} is too far in the future")
    return value


def _require_fields(
    value: Mapping[str, Any], allowed: frozenset[str], required: Iterable[str]
) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise SecurityError("unknown critical field: " + sorted(unknown)[0])
    missing = set(required) - set(value)
    if missing:
        raise SecurityError("missing field: " + sorted(missing)[0])


def sign_export(
    revision: Mapping[str, Any],
    identity: AuthorIdentity,
    *,
    project: str,
    scope: str,
    recipient: str,
    policy_digest: str,
    policy_version: int,
    expires_at: int,
    parents: Iterable[str] = (),
) -> dict[str, Any]:
    """Return an immutable, recipient- and policy-bound signed export."""
    now = int(time.time())
    if expires_at <= now or expires_at > now + MAX_LIFETIME_SECONDS:
        raise SecurityError("export expiry must be in the next 31 days")
    parent_list = list(parents)
    if len(parent_list) > 64:
        raise SecurityError("too many parent revisions")
    for parent in parent_list:
        _check_digest(parent, "parent digest")
    body: dict[str, Any] = {
        "format": FORMAT,
        "revision": copy.deepcopy(dict(revision)),
        "project": _check_identifier(project, "project"),
        "scope": _check_identifier(scope, "scope"),
        "recipient": _check_identifier(recipient, "recipient"),
        "policy_digest": _check_digest(policy_digest, "policy digest"),
        "policy_version": _check_time(policy_version, "policy version"),
        "created_at": now,
        "expires_at": _check_time(expires_at, "expiry"),
        "parents": parent_list,
        "author_key_id": identity.key_id,
        "author_public_key": _b64e(identity.public_key),
    }
    validate_export_shape(body, now=now, allow_unsigned=True)
    body["signature"] = _b64e(_private(identity).sign(canonical_bytes(body)))
    return body


def validate_export_shape(
    export: Mapping[str, Any], *, now: int | None = None, allow_unsigned: bool = False
) -> None:
    validate_json_value(export)
    required = EXPORT_FIELDS - ({"signature"} if allow_unsigned else set())
    _require_fields(export, EXPORT_FIELDS, required)
    if export.get("format") != FORMAT:
        raise SecurityError("unsupported export format")
    for field in ("project", "scope", "recipient"):
        _check_identifier(export.get(field), field)
    _check_digest(export.get("policy_digest"), "policy digest")
    _check_time(export.get("policy_version"), "policy version")
    created = _check_time(export.get("created_at"), "created at", now)
    expires = _check_time(export.get("expires_at"), "expiry")
    if expires <= created or (now is not None and expires <= now):
        raise SecurityError("export is expired")
    if expires > created + MAX_LIFETIME_SECONDS:
        raise SecurityError("export lifetime exceeds the 31-day maximum")
    _check_digest(export.get("author_key_id"), "author key id")
    public = _b64d(export.get("author_public_key"), 64)
    if hashlib.sha256(public).hexdigest() != export["author_key_id"]:
        raise SecurityError("author key identifier mismatch")
    if not isinstance(export.get("parents"), list) or len(export["parents"]) > 64:
        raise SecurityError("invalid parent list")
    for parent in export["parents"]:
        _check_digest(parent, "parent digest")
    if not allow_unsigned:
        signature = _b64d(export.get("signature"), MAX_SIGNATURE)
        if len(signature) != 64:
            raise SecurityError("invalid export signature")


def verify_export(
    export: Mapping[str, Any],
    *,
    trusted_keys: Mapping[str, bytes] | None = None,
    revoked_keys: Iterable[str] = (),
    project: str | None = None,
    scope: str | None = None,
    recipient: str | None = None,
    policy_digest: str | None = None,
    min_policy_version: int | None = None,
    now: int | None = None,
) -> QuarantinedExport:
    """Verify an export and return quarantine data only; never merge or execute it."""
    now = int(time.time()) if now is None else now
    validate_export_shape(export, now=now)
    author = str(export["author_key_id"])
    if author in set(revoked_keys):
        raise SecurityError("author key is revoked")
    embedded = _b64d(export["author_public_key"], 64)
    if trusted_keys is not None:
        trusted = trusted_keys.get(author)
        if trusted is None or trusted != embedded:
            raise SecurityError("author key is not trusted")
    for field, expected in (
        ("project", project),
        ("scope", scope),
        ("recipient", recipient),
        ("policy_digest", policy_digest),
    ):
        if expected is not None and export[field] != expected:
            raise SecurityError(f"export {field} does not match requested boundary")
    if (
        min_policy_version is not None
        and int(export["policy_version"]) < min_policy_version
    ):
        raise SecurityError("export policy version is stale")
    try:
        _public(embedded).verify(
            _b64d(export["signature"], MAX_SIGNATURE),
            canonical_bytes(_without_signature(export)),
        )
    except _crypto()[3] as error:
        raise SecurityError("export signature verification failed") from error
    return QuarantinedExport(
        copy.deepcopy(dict(export)), digest(_without_signature(export)), author
    )


def create_disclosure_grant(
    identity: AuthorIdentity,
    *,
    pack_digest: str,
    project: str,
    scope: str,
    recipient: str,
    policy_digest: str,
    policy_version: int,
    expires_at: int,
    operations: Iterable[str] = ("read",),
    delegable: bool = False,
) -> dict[str, Any]:
    now = int(time.time())
    if delegable:
        raise SecurityError("delegation is disabled by default and unsupported")
    operations_list = list(operations)
    if not operations_list or set(operations_list) - {"read", "review", "merge"}:
        raise SecurityError("invalid disclosure operations")
    if expires_at <= now or expires_at > now + MAX_LIFETIME_SECONDS:
        raise SecurityError("grant expiry must be in the next 31 days")
    grant: dict[str, Any] = {
        "format": FORMAT,
        "kind": "disclosure-grant",
        "grant_id": secrets.token_hex(16),
        "pack_digest": _check_digest(pack_digest, "pack digest"),
        "project": _check_identifier(project, "project"),
        "scope": _check_identifier(scope, "scope"),
        "recipient": _check_identifier(recipient, "recipient"),
        "operations": sorted(set(operations_list)),
        "policy_digest": _check_digest(policy_digest, "policy digest"),
        "policy_version": _check_time(policy_version, "policy version"),
        "issued_at": now,
        "expires_at": _check_time(expires_at, "expiry"),
        "delegable": False,
        "issuer_key_id": identity.key_id,
        "issuer_public_key": _b64e(identity.public_key),
    }
    validate_grant_shape(grant, now=now, allow_unsigned=True)
    grant["signature"] = _b64e(_private(identity).sign(canonical_bytes(grant)))
    return grant


def validate_grant_shape(
    grant: Mapping[str, Any], *, now: int | None = None, allow_unsigned: bool = False
) -> None:
    validate_json_value(grant)
    required = GRANT_FIELDS - ({"signature"} if allow_unsigned else set())
    _require_fields(grant, GRANT_FIELDS, required)
    if grant.get("format") != FORMAT or grant.get("kind") != "disclosure-grant":
        raise SecurityError("unsupported disclosure grant")
    for field in ("grant_id", "project", "scope", "recipient"):
        _check_identifier(grant.get(field), field)
    _check_digest(grant.get("pack_digest"), "pack digest")
    _check_digest(grant.get("policy_digest"), "policy digest")
    _check_time(grant.get("policy_version"), "policy version")
    issued, expires = (
        _check_time(grant.get("issued_at"), "issued at", now),
        _check_time(grant.get("expires_at"), "expiry"),
    )
    if (
        expires <= issued
        or (now is not None and expires <= now)
        or expires > issued + MAX_LIFETIME_SECONDS
        or grant.get("delegable") is not False
    ):
        raise SecurityError("invalid or expired disclosure grant")
    if (
        not isinstance(grant.get("operations"), list)
        or not grant["operations"]
        or set(grant["operations"]) - {"read", "review", "merge"}
    ):
        raise SecurityError("invalid disclosure operations")
    _check_digest(grant.get("issuer_key_id"), "issuer key id")
    public = _b64d(grant.get("issuer_public_key"), 64)
    if hashlib.sha256(public).hexdigest() != grant["issuer_key_id"]:
        raise SecurityError("issuer key identifier mismatch")
    if not allow_unsigned and len(_b64d(grant.get("signature"), MAX_SIGNATURE)) != 64:
        raise SecurityError("invalid grant signature")


def verify_disclosure_grant(
    grant: Mapping[str, Any],
    *,
    pack_digest: str,
    project: str,
    scope: str,
    recipient: str,
    policy_digest: str,
    min_policy_version: int,
    required_operation: str = "read",
    expected_issuer_key_id: str | None = None,
    trusted_keys: Mapping[str, bytes] | None = None,
    revoked_keys: Iterable[str] = (),
    now: int | None = None,
) -> None:
    now = int(time.time()) if now is None else now
    validate_grant_shape(grant, now=now)
    issuer = str(grant["issuer_key_id"])
    if expected_issuer_key_id is not None and issuer != expected_issuer_key_id:
        raise SecurityError("grant issuer does not match export author")
    if issuer in set(revoked_keys):
        raise SecurityError("grant issuer key is revoked")
    embedded = _b64d(grant["issuer_public_key"], 64)
    if trusted_keys is not None and trusted_keys.get(issuer) != embedded:
        raise SecurityError("grant issuer is not trusted")
    expected = {
        "pack_digest": pack_digest,
        "project": project,
        "scope": scope,
        "recipient": recipient,
        "policy_digest": policy_digest,
    }
    if any(grant[field] != value for field, value in expected.items()):
        raise SecurityError("grant is not for this exact disclosure")
    if (
        int(grant["policy_version"]) < min_policy_version
        or required_operation not in grant["operations"]
    ):
        raise SecurityError("grant does not authorize requested operation")
    try:
        _public(embedded).verify(
            _b64d(grant["signature"], MAX_SIGNATURE),
            canonical_bytes(_without_signature(grant)),
        )
    except _crypto()[3] as error:
        raise SecurityError("grant signature verification failed") from error


class PolicyVersionStore:
    """Fail-closed monotonic policy tracker; older or equivocated policies are denied."""

    def __init__(self) -> None:
        self._seen: dict[str, tuple[int, str]] = {}

    def accept(self, project: str, version: int, policy_digest: str) -> None:
        project, policy_digest = (
            _check_identifier(project, "project"),
            _check_digest(policy_digest, "policy digest"),
        )
        version = _check_time(version, "policy version")
        previous = self._seen.get(project)
        if previous is not None and (
            version < previous[0]
            or (version == previous[0] and policy_digest != previous[1])
        ):
            raise SecurityError("policy rollback or equivocation detected")
        self._seen[project] = (version, policy_digest)

    def minimum(self, project: str) -> tuple[int, str] | None:
        return self._seen.get(project)


def validate_json_value(
    value: Any,
    *,
    max_depth: int = MAX_DEPTH,
    max_nodes: int = MAX_NODES,
    max_string: int = MAX_STRING,
    allowed_fields: set[str] | None = None,
) -> None:
    """Bounded JSON tree validation.  Rejects unsupported values and critical unknown fields."""
    if max_depth < 1 or max_nodes < 1 or max_string < 1:
        raise SecurityError("invalid JSON limits")
    nodes = 0

    def walk(item: Any, depth: int, root: bool = False) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise SecurityError("JSON structure exceeds safety limit")
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, int):
            if abs(item) > 2**63 - 1:
                raise SecurityError("JSON integer exceeds safety limit")
            return
        if isinstance(item, float):
            raise SecurityError("JSON floats are not canonical")
        if isinstance(item, str):
            if len(item) > max_string or "\x00" in item:
                raise SecurityError("JSON string exceeds safety limit")
            return
        if isinstance(item, list):
            if len(item) > MAX_COLLECTION:
                raise SecurityError("JSON collection exceeds safety limit")
            for member in item:
                walk(member, depth + 1)
            return
        if isinstance(item, dict):
            if len(item) > MAX_COLLECTION:
                raise SecurityError("JSON collection exceeds safety limit")
            if root and allowed_fields is not None and set(item) - allowed_fields:
                raise SecurityError("unknown critical field")
            for key, member in item.items():
                if not isinstance(key, str) or len(key) > 256 or "\x00" in key:
                    raise SecurityError("invalid JSON object key")
                walk(member, depth + 1)
            return
        raise SecurityError("unsupported JSON value")

    walk(value, 0, True)


def strict_json_loads(
    raw: str | bytes, *, allowed_fields: set[str] | None = None
) -> Any:
    """Parse JSON while rejecting duplicate keys and then apply bounded validation."""

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, member in pairs:
            if key in value:
                raise SecurityError("duplicate JSON key")
            value[key] = member
        return value

    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=no_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(
                SecurityError("invalid JSON constant")
            ),
        )
    except SecurityError:
        raise
    except (TypeError, UnicodeDecodeError, ValueError, RecursionError) as error:
        # json.loads raises RecursionError on deeply nested input and a bare
        # ValueError on an over-length integer literal, both BEFORE
        # validate_json_value can bound them.  Fail closed so no caller sees a
        # non-SecurityError escape (which would wedge fail-closed receive loops).
        raise SecurityError("invalid JSON") from error
    validate_json_value(parsed, allowed_fields=allowed_fields)
    return parsed


def scan_sensitive(value: Any, path: str = "$") -> list[dict[str, str]]:
    """Recursively scan data before storage/logging/transmission; findings contain no secret."""
    validate_json_value(value)
    findings: list[dict[str, str]] = []

    def walk(item: Any, location: str) -> None:
        if isinstance(item, str):
            for label, pattern in SENSITIVE_PATTERNS:
                if pattern.search(item):
                    findings.append({"kind": label, "path": location})
            return
        if isinstance(item, list):
            for index, member in enumerate(item):
                walk(member, f"{location}[{index}]")
        elif isinstance(item, dict):
            for key, member in item.items():
                if re.search(
                    r"(?:password|secret|token|api[_-]?key|private[_-]?key)",
                    key,
                    re.IGNORECASE,
                ):
                    findings.append(
                        {"kind": "sensitive-key-name", "path": f"{location}.{key}"}
                    )
                walk(member, f"{location}.{key}")

    walk(value, path)
    return findings


def redact_sensitive(value: Any) -> tuple[Any, list[dict[str, str]]]:
    """Return a deep copy with each detected sensitive value replaced by a fixed marker."""
    validate_json_value(value)
    findings = scan_sensitive(value)

    def redact(item: Any) -> Any:
        if isinstance(item, str):
            return (
                "[REDACTED]"
                if any(pattern.search(item) for _, pattern in SENSITIVE_PATTERNS)
                else item
            )
        if isinstance(item, list):
            return [redact(member) for member in item]
        if isinstance(item, dict):
            return {
                key: "[REDACTED]"
                if re.search(
                    r"(?:password|secret|token|api[_-]?key|private[_-]?key)",
                    key,
                    re.IGNORECASE,
                )
                else redact(member)
                for key, member in item.items()
            }
        return item

    return redact(value), findings
