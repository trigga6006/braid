"""Self-hosted asynchronous mailbox for governed Session Bridge Context Packs.

The hub is deliberately blind infrastructure. It authenticates enrolled endpoint
identities and routes opaque endpoint-encrypted envelopes, but it never imports,
indexes, merges, or interprets Context Ledger state.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import closing, contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import ssl
import sys
import threading
import time
from typing import Any, Iterator, Mapping
from urllib.parse import urlsplit

from context_security import (
    AuthorIdentity,
    SecurityError,
    canonical_bytes,
    create_identity_assertion,
    identity_principal,
    load_or_create_identity,
    validate_json_value,
    verify_identity_assertion,
)


HUB_FORMAT = "session-bridge-team-hub/v1"
ENROLLMENT_FORMAT = "session-bridge-team-enrollment/v1"
REQUEST_FORMAT = "session-bridge-team-request/v1"
ENVELOPE_FORMAT = "session-bridge-team-envelope/v1"
MAX_HTTP_BODY = 2_000_000
MAX_ENVELOPE_BYTES = 1_500_000
MAX_PAGE = 100
REQUEST_WINDOW_SECONDS = 300
REQUEST_TIMEOUT_SECONDS = 15
MAX_MESSAGE_TTL_SECONDS = 31 * 24 * 3600
DEFAULT_MESSAGE_TTL_SECONDS = 7 * 24 * 3600
MAX_PROJECT_ENDPOINTS = 1_000
MAX_ACTIVE_ENROLLMENTS = 1_000
MAX_PENDING_MESSAGES = 10_000
MAX_PENDING_BYTES = 256 * 1024 * 1024
# Per-(recipient, sender) sub-quota so one member cannot fill a peer's whole
# mailbox and deny delivery to every other sender.
MAX_PENDING_PER_SENDER_MESSAGES = 2_000
MAX_PENDING_PER_SENDER_BYTES = 64 * 1024 * 1024
# Hard ceiling on total time a single connection may occupy a worker thread,
# so a slow/dribbling (slowloris) client cannot pin a worker slot indefinitely.
CONNECTION_DEADLINE_SECONDS = 30
RECEIPT_RETENTION_SECONDS = 30 * 24 * 3600
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
NONCE = re.compile(r"^[0-9a-f]{32}$")
PRINCIPAL = re.compile(r"^ed25519:[0-9a-f]{64}$")


class HubError(ValueError):
    """Expected protocol or policy rejection with an HTTP status and safe code."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class HubRateLimiter:
    """Small in-memory abuse limiter; durable identity checks remain authoritative."""

    def __init__(self, maximum_keys: int = 20_000) -> None:
        self.maximum_keys = maximum_keys
        self._events: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            values = [value for value in self._events.get(key, []) if value > cutoff]
            if len(values) >= limit:
                self._events[key] = values
                return False
            values.append(now)
            self._events[key] = values
            if len(self._events) > self.maximum_keys:
                oldest = min(
                    self._events,
                    key=lambda candidate: self._events[candidate][-1],
                )
                self._events.pop(oldest, None)
            return True


def _now() -> int:
    return int(time.time())


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64d(value: Any, *, maximum: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum * 2:
        raise HubError(400, "invalid_base64", "Invalid encoded value.")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (TypeError, ValueError) as error:
        raise HubError(400, "invalid_base64", "Invalid encoded value.") from error
    if len(decoded) > maximum:
        raise HubError(413, "encoded_value_too_large", "Encoded value is too large.")
    return decoded


def _canonical(value: Mapping[str, Any]) -> bytes:
    try:
        return canonical_bytes(value)
    except SecurityError as error:
        raise HubError(400, "invalid_json_shape", str(error)) from error


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise HubError(400, "invalid_identifier", f"Invalid {field}.")
    return value


def _principal(value: Any, field: str = "principal") -> str:
    if not isinstance(value, str) or not PRINCIPAL.fullmatch(value):
        raise HubError(400, "invalid_principal", f"Invalid {field}.")
    return value


def _label(value: Any, field: str = "label") -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 120
        or any(ord(character) < 32 for character in value)
    ):
        raise HubError(400, "invalid_label", f"Invalid {field}.")
    return value.strip()


def _positive_int(value: Any, field: str, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise HubError(400, "invalid_integer", f"Invalid {field}.")
    if maximum is not None and value > maximum:
        raise HubError(400, "invalid_integer", f"Invalid {field}.")
    return value


def _json_loads(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_HTTP_BODY:
        raise HubError(413, "request_too_large", "Request body is too large.")

    def reject_duplicates(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise HubError(400, "duplicate_json_key", "Duplicate JSON key.")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except UnicodeDecodeError as error:
        raise HubError(400, "invalid_utf8", "Request must be UTF-8 JSON.") from error
    except json.JSONDecodeError as error:
        raise HubError(400, "invalid_json", "Request must be valid JSON.") from error
    if not isinstance(value, dict):
        raise HubError(400, "invalid_request", "Request must be a JSON object.")
    try:
        validate_json_value(value)
    except SecurityError as error:
        raise HubError(400, "invalid_json_shape", str(error)) from error
    return value


def encode_enrollment_code(payload: Mapping[str, Any]) -> str:
    value = dict(payload)
    if value.get("format") != ENROLLMENT_FORMAT:
        raise HubError(400, "invalid_enrollment", "Invalid enrollment payload.")
    return "SBH1." + _b64e(_canonical(value))


def decode_enrollment_code(code: str) -> dict[str, Any]:
    if not isinstance(code, str) or not code.startswith("SBH1."):
        raise HubError(400, "invalid_enrollment", "Invalid Team Hub enrollment code.")
    raw = _b64d(code[5:].strip(), maximum=4096)
    value = _json_loads(raw)
    required = {
        "format",
        "server_url",
        "server_principal",
        "project_id",
        "secret",
        "expires_at",
    }
    if set(value) != required or value.get("format") != ENROLLMENT_FORMAT:
        raise HubError(400, "invalid_enrollment", "Invalid Team Hub enrollment code.")
    _validate_server_url(value["server_url"])
    _identifier(value["project_id"], "project ID")
    _principal(value["server_principal"], "server identity")
    if not isinstance(value["secret"], str) or len(value["secret"]) < 32:
        raise HubError(400, "invalid_enrollment", "Invalid enrollment secret.")
    expires = _positive_int(value["expires_at"], "enrollment expiry")
    if expires <= _now():
        raise HubError(410, "enrollment_expired", "Enrollment code has expired.")
    return value


def _validate_server_url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise HubError(400, "invalid_server_url", "Invalid Team Hub URL.")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HubError(400, "invalid_server_url", "Invalid Team Hub URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise HubError(400, "invalid_server_url", "Invalid Team Hub URL.")
    if parsed.scheme == "http" and parsed.hostname not in {
        "127.0.0.1",
        "localhost",
        "::1",
    }:
        raise HubError(
            400,
            "insecure_server_url",
            "Non-loopback Team Hub URLs must use HTTPS.",
        )
    return value.rstrip("/")


def _make_id(prefix: str) -> str:
    return prefix + "_" + secrets.token_hex(12)


class HubStore:
    """Transactional single-node Team Hub storage."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            self.root.chmod(0o700)
        except OSError:
            pass
        self.database = self.root / "hub.sqlite3"
        self.identity: AuthorIdentity = load_or_create_identity(
            self.root / "server-identity.json"
        )
        self.server_principal = identity_principal(self.identity)
        self._schema_lock = threading.Lock()
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database,
            timeout=30,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _ensure_schema(self) -> None:
        with self._schema_lock, closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS teams (
                    team_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS projects (
                    project_id TEXT PRIMARY KEY,
                    team_id TEXT NOT NULL REFERENCES teams(team_id),
                    name TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    UNIQUE(team_id, name)
                );
                CREATE TABLE IF NOT EXISTS endpoints (
                    principal TEXT PRIMARY KEY,
                    signing_public_key TEXT NOT NULL,
                    mailbox_public_key TEXT NOT NULL,
                    label TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'disabled')),
                    created_at INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS memberships (
                    project_id TEXT NOT NULL REFERENCES projects(project_id),
                    principal TEXT NOT NULL REFERENCES endpoints(principal),
                    role TEXT NOT NULL CHECK(role IN ('member', 'project-agent', 'admin')),
                    mailbox_binding TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY(project_id, principal)
                );
                CREATE TABLE IF NOT EXISTS enrollments (
                    enrollment_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES projects(project_id),
                    secret_digest TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('member', 'project-agent', 'admin')),
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    used_at INTEGER,
                    used_by TEXT
                );
                CREATE TABLE IF NOT EXISTS messages (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id TEXT NOT NULL UNIQUE,
                    project_id TEXT NOT NULL REFERENCES projects(project_id),
                    sender TEXT NOT NULL REFERENCES endpoints(principal),
                    recipient TEXT NOT NULL REFERENCES endpoints(principal),
                    kind TEXT NOT NULL,
                    envelope_digest TEXT NOT NULL,
                    envelope BLOB,
                    state TEXT NOT NULL CHECK(state IN ('pending', 'acked', 'expired')),
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    delivered_at INTEGER,
                    acked_at INTEGER
                );
                CREATE INDEX IF NOT EXISTS mailbox_pending
                    ON messages(project_id, recipient, state, sequence);
                CREATE TABLE IF NOT EXISTS request_nonces (
                    principal TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    used_at INTEGER NOT NULL,
                    PRIMARY KEY(principal, nonce)
                );
                CREATE TABLE IF NOT EXISTS audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    event TEXT NOT NULL,
                    details TEXT NOT NULL,
                    previous_digest TEXT NOT NULL,
                    digest TEXT NOT NULL UNIQUE
                );
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO metadata(key, value) VALUES('schema', ?)",
                (HUB_FORMAT,),
            )
            schema = connection.execute(
                "SELECT value FROM metadata WHERE key = 'schema'"
            ).fetchone()
            if schema is None or schema["value"] != HUB_FORMAT:
                raise RuntimeError("Unsupported Team Hub database schema.")
            membership_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(memberships)"
                ).fetchall()
            }
            if "mailbox_binding" not in membership_columns:
                raise RuntimeError(
                    "Unsupported pre-release Team Hub database schema; back up and "
                    "recreate the Hub before enrolling endpoints."
                )

    def _audit(
        self, connection: sqlite3.Connection, event: str, details: Mapping[str, Any]
    ) -> None:
        previous = connection.execute(
            "SELECT digest FROM audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_digest = previous["digest"] if previous else "0" * 64
        record = {
            "created_at": _now(),
            "event": _identifier(event, "audit event"),
            "details": dict(details),
            "previous_digest": previous_digest,
        }
        record_digest = _digest(record)
        connection.execute(
            """INSERT INTO audit(created_at, event, details, previous_digest, digest)
               VALUES(?, ?, ?, ?, ?)""",
            (
                record["created_at"],
                record["event"],
                json.dumps(record["details"], sort_keys=True, separators=(",", ":")),
                previous_digest,
                record_digest,
            ),
        )

    def initialize(self, team_name: str, project_name: str) -> dict[str, Any]:
        team_name, project_name = (
            _label(team_name, "team name"),
            _label(project_name, "project name"),
        )
        now = _now()
        with self.transaction() as connection:
            team = connection.execute(
                "SELECT team_id FROM teams WHERE name = ?", (team_name,)
            ).fetchone()
            if team is None:
                team_id = _make_id("team")
                connection.execute(
                    "INSERT INTO teams(team_id, name, created_at) VALUES(?, ?, ?)",
                    (team_id, team_name, now),
                )
                self._audit(
                    connection, "team-created", {"team_id": team_id, "name": team_name}
                )
            else:
                team_id = str(team["team_id"])
            project = connection.execute(
                "SELECT project_id FROM projects WHERE team_id = ? AND name = ?",
                (team_id, project_name),
            ).fetchone()
            if project is None:
                project_id = _make_id("project")
                connection.execute(
                    """INSERT INTO projects(project_id, team_id, name, created_at)
                       VALUES(?, ?, ?, ?)""",
                    (project_id, team_id, project_name, now),
                )
                self._audit(
                    connection,
                    "project-created",
                    {
                        "team_id": team_id,
                        "project_id": project_id,
                        "name": project_name,
                    },
                )
            else:
                project_id = str(project["project_id"])
        return {
            "format": HUB_FORMAT,
            "team_id": team_id,
            "team": team_name,
            "project_id": project_id,
            "project": project_name,
            "server_principal": self.server_principal,
        }

    def create_enrollment(
        self,
        project_id: str,
        label: str,
        role: str,
        server_url: str,
        expires_seconds: int = 3600,
    ) -> dict[str, Any]:
        project_id = _identifier(project_id, "project ID")
        label = _label(label)
        if role not in {"member", "project-agent", "admin"}:
            raise HubError(400, "invalid_role", "Invalid enrollment role.")
        server_url = _validate_server_url(server_url)
        expires_seconds = _positive_int(
            expires_seconds, "enrollment lifetime", maximum=7 * 24 * 3600
        )
        now, secret = _now(), secrets.token_urlsafe(32)
        secret_digest = hashlib.sha256(secret.encode("ascii")).hexdigest()
        enrollment_id = _make_id("enroll")
        with self.transaction() as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM projects WHERE project_id = ?", (project_id,)
                ).fetchone()
                is None
            ):
                raise HubError(404, "project_not_found", "Project does not exist.")
            active = connection.execute(
                """SELECT COUNT(*) AS count FROM enrollments
                   WHERE project_id = ? AND used_at IS NULL AND expires_at > ?""",
                (project_id, now),
            ).fetchone()
            if int(active["count"]) >= MAX_ACTIVE_ENROLLMENTS:
                raise HubError(
                    429,
                    "too_many_enrollments",
                    "Project has too many active enrollment codes.",
                )
            connection.execute(
                """INSERT INTO enrollments(
                       enrollment_id, project_id, secret_digest, label, role,
                       created_at, expires_at
                   ) VALUES(?, ?, ?, ?, ?, ?, ?)""",
                (
                    enrollment_id,
                    project_id,
                    secret_digest,
                    label,
                    role,
                    now,
                    now + expires_seconds,
                ),
            )
            self._audit(
                connection,
                "enrollment-created",
                {
                    "enrollment_id": enrollment_id,
                    "project_id": project_id,
                    "label": label,
                    "role": role,
                    "expires_at": now + expires_seconds,
                },
            )
        payload = {
            "format": ENROLLMENT_FORMAT,
            "server_url": server_url,
            "server_principal": self.server_principal,
            "project_id": project_id,
            "secret": secret,
            "expires_at": now + expires_seconds,
        }
        return {
            "enrollment_id": enrollment_id,
            "project_id": project_id,
            "label": label,
            "role": role,
            "expires_at": payload["expires_at"],
            "code": encode_enrollment_code(payload),
        }

    def resolve_project(self, team_name: str, project_name: str) -> str:
        team_name, project_name = (
            _label(team_name, "team name"),
            _label(project_name, "project name"),
        )
        with closing(self._connect()) as connection:
            row = connection.execute(
                """SELECT p.project_id FROM projects p
                   JOIN teams t USING(team_id)
                   WHERE t.name = ? AND p.name = ?""",
                (team_name, project_name),
            ).fetchone()
        if row is None:
            raise HubError(404, "project_not_found", "Project does not exist.")
        return str(row["project_id"])

    def redeem_enrollment(self, request: Mapping[str, Any]) -> dict[str, Any]:
        required = {"code", "mailbox_public_key", "identity", "mailbox_binding"}
        if set(request) != required:
            raise HubError(400, "invalid_enrollment", "Invalid enrollment request.")
        code = decode_enrollment_code(str(request["code"]))
        if code["server_principal"] != self.server_principal:
            raise HubError(400, "wrong_server", "Enrollment code is for another hub.")
        mailbox_public_key = str(request["mailbox_public_key"])
        if len(_b64d(mailbox_public_key, maximum=64)) != 32:
            raise HubError(400, "invalid_mailbox_key", "Invalid mailbox public key.")
        secret_digest = hashlib.sha256(str(code["secret"]).encode("ascii")).hexdigest()
        subject = {
            "action": "team-hub-enroll",
            "project_id": code["project_id"],
            "server_principal": self.server_principal,
            "mailbox_public_key": mailbox_public_key,
            "secret_digest": secret_digest,
            "expires_at": code["expires_at"],
        }
        identity = request["identity"]
        if not isinstance(identity, Mapping):
            raise HubError(400, "invalid_identity", "Invalid endpoint identity.")
        try:
            principal = verify_identity_assertion(identity, subject)
        except SecurityError as error:
            raise HubError(401, "identity_verification_failed", str(error)) from error
        mailbox_binding = request["mailbox_binding"]
        if not isinstance(mailbox_binding, Mapping):
            raise HubError(400, "invalid_identity", "Invalid mailbox key binding.")
        binding_subject = {
            "action": "team-hub-mailbox-binding",
            "project_id": code["project_id"],
            "server_principal": self.server_principal,
            "mailbox_public_key": mailbox_public_key,
        }
        try:
            binding_principal = verify_identity_assertion(
                mailbox_binding, binding_subject
            )
        except SecurityError as error:
            raise HubError(401, "identity_verification_failed", str(error)) from error
        if binding_principal != principal:
            raise HubError(
                401,
                "identity_verification_failed",
                "Mailbox key binding uses another endpoint identity.",
            )
        signing_public_key = str(identity.get("public_key", ""))
        now = _now()
        with self.transaction() as connection:
            enrollment = connection.execute(
                "SELECT * FROM enrollments WHERE secret_digest = ?", (secret_digest,)
            ).fetchone()
            if enrollment is None or enrollment["project_id"] != code["project_id"]:
                raise HubError(404, "enrollment_not_found", "Enrollment was not found.")
            if int(enrollment["expires_at"]) <= now:
                raise HubError(
                    410, "enrollment_expired", "Enrollment code has expired."
                )
            if enrollment["used_at"] is not None and enrollment["used_by"] != principal:
                raise HubError(
                    409, "enrollment_used", "Enrollment code was already used."
                )
            endpoint = connection.execute(
                "SELECT * FROM endpoints WHERE principal = ?", (principal,)
            ).fetchone()
            if endpoint is not None and (
                endpoint["signing_public_key"] != signing_public_key
                or endpoint["mailbox_public_key"] != mailbox_public_key
            ):
                raise HubError(
                    409,
                    "endpoint_key_conflict",
                    "Endpoint principal is already bound to different keys.",
                )
            membership = connection.execute(
                """SELECT role, mailbox_binding FROM memberships
                   WHERE project_id = ? AND principal = ?""",
                (enrollment["project_id"], principal),
            ).fetchone()
            if membership is None:
                members = connection.execute(
                    "SELECT COUNT(*) AS count FROM memberships WHERE project_id = ?",
                    (enrollment["project_id"],),
                ).fetchone()
                if int(members["count"]) >= MAX_PROJECT_ENDPOINTS:
                    raise HubError(
                        409,
                        "project_full",
                        "Project endpoint limit has been reached.",
                    )
            elif membership["role"] != enrollment["role"]:
                raise HubError(
                    409,
                    "membership_role_conflict",
                    "Endpoint already has a different role in this project.",
                )
            if endpoint is None:
                connection.execute(
                    """INSERT INTO endpoints(
                           principal, signing_public_key, mailbox_public_key, label,
                           status, created_at, last_seen_at
                       ) VALUES(?, ?, ?, ?, 'active', ?, ?)""",
                    (
                        principal,
                        signing_public_key,
                        mailbox_public_key,
                        enrollment["label"],
                        now,
                        now,
                    ),
                )
            if membership is None:
                connection.execute(
                    """INSERT INTO memberships(
                           project_id, principal, role, mailbox_binding, created_at
                       ) VALUES(?, ?, ?, ?, ?)""",
                    (
                        enrollment["project_id"],
                        principal,
                        enrollment["role"],
                        json.dumps(
                            mailbox_binding, sort_keys=True, separators=(",", ":")
                        ),
                        now,
                    ),
                )
            connection.execute(
                "UPDATE enrollments SET used_at = ?, used_by = ? WHERE enrollment_id = ?",
                (now, principal, enrollment["enrollment_id"]),
            )
            self._audit(
                connection,
                "endpoint-enrolled",
                {
                    "project_id": enrollment["project_id"],
                    "principal": principal,
                    "role": enrollment["role"],
                    "enrollment_id": enrollment["enrollment_id"],
                },
            )
            result = {
                "project_id": enrollment["project_id"],
                "principal": principal,
                "label": enrollment["label"],
                "role": enrollment["role"],
                "server_principal": self.server_principal,
            }
        return result

    def authenticate(
        self, path: str, wrapper: Mapping[str, Any]
    ) -> tuple[str, dict[str, Any], str]:
        if (
            set(wrapper) != {"format", "body", "auth"}
            or wrapper.get("format") != REQUEST_FORMAT
        ):
            raise HubError(400, "invalid_request", "Invalid authenticated request.")
        body, auth = wrapper["body"], wrapper["auth"]
        if not isinstance(body, dict) or not isinstance(auth, dict):
            raise HubError(400, "invalid_request", "Invalid authenticated request.")
        if set(auth) != {"timestamp", "nonce", "identity"}:
            raise HubError(400, "invalid_auth", "Invalid request authentication.")
        timestamp = auth["timestamp"]
        if isinstance(timestamp, bool) or not isinstance(timestamp, int):
            raise HubError(400, "invalid_auth", "Invalid authentication timestamp.")
        now = _now()
        if abs(now - timestamp) > REQUEST_WINDOW_SECONDS:
            raise HubError(
                401, "stale_request", "Request timestamp is outside the window."
            )
        nonce = str(auth["nonce"])
        if not NONCE.fullmatch(nonce):
            raise HubError(400, "invalid_auth", "Invalid request nonce.")
        assertion = auth["identity"]
        if not isinstance(assertion, Mapping):
            raise HubError(400, "invalid_identity", "Invalid endpoint identity.")
        subject = {
            "action": "team-hub-request",
            "path": path,
            "body_sha256": _digest(body),
            "timestamp": timestamp,
            "nonce": nonce,
        }
        try:
            principal = verify_identity_assertion(assertion, subject)
        except SecurityError as error:
            raise HubError(401, "identity_verification_failed", str(error)) from error
        signing_public_key = str(assertion.get("public_key", ""))
        with self.transaction() as connection:
            endpoint = connection.execute(
                "SELECT * FROM endpoints WHERE principal = ?", (principal,)
            ).fetchone()
            if endpoint is None or endpoint["status"] != "active":
                raise HubError(403, "endpoint_not_active", "Endpoint is not active.")
            if endpoint["signing_public_key"] != signing_public_key:
                raise HubError(401, "identity_key_mismatch", "Endpoint key mismatch.")
            # Retain nonces for the full width the timestamp check can accept
            # (a client clock up to REQUEST_WINDOW_SECONDS ahead is admitted, so
            # a nonce must survive that long past its used_at or a replay could
            # slip through after eviction).
            connection.execute(
                "DELETE FROM request_nonces WHERE used_at < ?",
                (now - 2 * REQUEST_WINDOW_SECONDS,),
            )
            try:
                connection.execute(
                    "INSERT INTO request_nonces(principal, nonce, used_at) VALUES(?, ?, ?)",
                    (principal, nonce, now),
                )
            except sqlite3.IntegrityError as error:
                raise HubError(
                    409, "replayed_request", "Request nonce was reused."
                ) from error
            connection.execute(
                "UPDATE endpoints SET last_seen_at = ? WHERE principal = ?",
                (now, principal),
            )
        return principal, body, nonce

    @staticmethod
    def _membership(
        connection: sqlite3.Connection, project_id: str, principal: str
    ) -> sqlite3.Row:
        membership = connection.execute(
            """SELECT memberships.*, endpoints.status
               FROM memberships JOIN endpoints USING(principal)
               WHERE project_id = ? AND principal = ?""",
            (project_id, principal),
        ).fetchone()
        if membership is None or membership["status"] != "active":
            raise HubError(
                403, "not_a_project_member", "Endpoint is not a project member."
            )
        return membership

    def directory(self, principal: str, body: Mapping[str, Any]) -> dict[str, Any]:
        if set(body) != {"project_id"}:
            raise HubError(
                400, "invalid_directory_request", "Invalid directory request."
            )
        project_id = _identifier(body["project_id"], "project ID")
        with closing(self._connect()) as connection:
            self._membership(connection, project_id, principal)
            rows = connection.execute(
                """SELECT e.principal, e.mailbox_public_key, e.label, m.role
                   , m.mailbox_binding
                   FROM memberships m JOIN endpoints e USING(principal)
                   WHERE m.project_id = ? AND e.status = 'active'
                   ORDER BY e.label, e.principal""",
                (project_id,),
            ).fetchall()
        return {
            "project_id": project_id,
            "endpoints": [
                {
                    "principal": row["principal"],
                    "mailbox_public_key": row["mailbox_public_key"],
                    "label": row["label"],
                    "role": row["role"],
                    "mailbox_binding": json.loads(row["mailbox_binding"]),
                }
                for row in rows
            ],
        }

    @staticmethod
    def _validate_envelope(
        envelope: Mapping[str, Any], principal: str
    ) -> dict[str, Any]:
        required = {
            "format",
            "message_id",
            "project_id",
            "sender",
            "recipient",
            "kind",
            "created_at",
            "expires_at",
            "ephemeral_public_key",
            "nonce",
            "ciphertext",
        }
        if set(envelope) != required or envelope.get("format") != ENVELOPE_FORMAT:
            raise HubError(400, "invalid_envelope", "Invalid mailbox envelope.")
        value = dict(envelope)
        _identifier(value["message_id"], "message ID")
        _identifier(value["project_id"], "project ID")
        if value["sender"] != principal:
            raise HubError(
                403, "sender_mismatch", "Envelope sender does not match endpoint."
            )
        _principal(value["sender"], "envelope sender")
        _principal(value["recipient"], "envelope recipient")
        if value["kind"] not in {"context-pack", "coordination-note"}:
            raise HubError(400, "invalid_envelope", "Invalid envelope kind.")
        created = _positive_int(value["created_at"], "creation time")
        expires = _positive_int(value["expires_at"], "expiry")
        now = _now()
        if abs(now - created) > REQUEST_WINDOW_SECONDS:
            raise HubError(
                400, "invalid_envelope_time", "Envelope creation time is stale."
            )
        if expires <= now or expires > now + MAX_MESSAGE_TTL_SECONDS:
            raise HubError(400, "invalid_envelope_time", "Envelope expiry is invalid.")
        if len(_b64d(value["ephemeral_public_key"], maximum=64)) != 32:
            raise HubError(400, "invalid_envelope", "Invalid ephemeral public key.")
        if len(_b64d(value["nonce"], maximum=32)) != 12:
            raise HubError(400, "invalid_envelope", "Invalid envelope nonce.")
        ciphertext = _b64d(value["ciphertext"], maximum=MAX_ENVELOPE_BYTES)
        if len(ciphertext) < 17:
            raise HubError(400, "invalid_envelope", "Invalid envelope ciphertext.")
        return value

    def push(self, principal: str, body: Mapping[str, Any]) -> dict[str, Any]:
        if set(body) != {"envelope"} or not isinstance(body["envelope"], Mapping):
            raise HubError(400, "invalid_push", "Invalid mailbox push.")
        envelope = self._validate_envelope(body["envelope"], principal)
        serialized = _canonical(envelope)
        if len(serialized) > MAX_ENVELOPE_BYTES:
            raise HubError(413, "envelope_too_large", "Mailbox envelope is too large.")
        envelope_digest = hashlib.sha256(serialized).hexdigest()
        now = _now()
        with self.transaction() as connection:
            self._membership(connection, envelope["project_id"], principal)
            self._membership(connection, envelope["project_id"], envelope["recipient"])
            existing = connection.execute(
                "SELECT envelope_digest, state FROM messages WHERE message_id = ?",
                (envelope["message_id"],),
            ).fetchone()
            if existing is not None:
                if existing["envelope_digest"] != envelope_digest:
                    raise HubError(
                        409,
                        "message_id_conflict",
                        "Message ID is already bound to another envelope.",
                    )
                return {
                    "message_id": envelope["message_id"],
                    "state": existing["state"],
                    "idempotent": True,
                }
            pending = connection.execute(
                """SELECT COUNT(*) AS count, COALESCE(SUM(LENGTH(envelope)), 0) AS bytes
                   FROM messages
                   WHERE project_id = ? AND recipient = ? AND state = 'pending'""",
                (envelope["project_id"], envelope["recipient"]),
            ).fetchone()
            if (
                int(pending["count"]) >= MAX_PENDING_MESSAGES
                or int(pending["bytes"]) + len(serialized) > MAX_PENDING_BYTES
            ):
                raise HubError(
                    429,
                    "mailbox_capacity_exceeded",
                    "Recipient mailbox capacity has been reached.",
                )
            per_sender = connection.execute(
                """SELECT COUNT(*) AS count, COALESCE(SUM(LENGTH(envelope)), 0) AS bytes
                   FROM messages
                   WHERE project_id = ? AND recipient = ? AND sender = ?
                     AND state = 'pending'""",
                (envelope["project_id"], envelope["recipient"], principal),
            ).fetchone()
            if (
                int(per_sender["count"]) >= MAX_PENDING_PER_SENDER_MESSAGES
                or int(per_sender["bytes"]) + len(serialized)
                > MAX_PENDING_PER_SENDER_BYTES
            ):
                raise HubError(
                    429,
                    "sender_quota_exceeded",
                    "Per-sender mailbox quota for this recipient has been reached.",
                )
            connection.execute(
                """INSERT INTO messages(
                       message_id, project_id, sender, recipient, kind,
                       envelope_digest, envelope, state, created_at, expires_at
                   ) VALUES(?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
                (
                    envelope["message_id"],
                    envelope["project_id"],
                    principal,
                    envelope["recipient"],
                    envelope["kind"],
                    envelope_digest,
                    serialized,
                    now,
                    envelope["expires_at"],
                ),
            )
            self._audit(
                connection,
                "message-queued",
                {
                    "message_id": envelope["message_id"],
                    "project_id": envelope["project_id"],
                    "sender": principal,
                    "recipient": envelope["recipient"],
                    "kind": envelope["kind"],
                    "envelope_digest": envelope_digest,
                },
            )
        return {
            "message_id": envelope["message_id"],
            "state": "pending",
            "idempotent": False,
        }

    def _expire_messages(self, connection: sqlite3.Connection, now: int) -> int:
        rows = connection.execute(
            "SELECT message_id FROM messages WHERE state = 'pending' AND expires_at <= ?",
            (now,),
        ).fetchall()
        if not rows:
            return 0
        connection.execute(
            """UPDATE messages SET state = 'expired', envelope = NULL
               WHERE state = 'pending' AND expires_at <= ?""",
            (now,),
        )
        self._audit(
            connection,
            "messages-expired",
            {"count": len(rows), "through": now},
        )
        return len(rows)

    def pull(self, principal: str, body: Mapping[str, Any]) -> dict[str, Any]:
        if set(body) - {"project_id", "after", "limit"} or "project_id" not in body:
            raise HubError(400, "invalid_pull", "Invalid mailbox pull.")
        project_id = _identifier(body["project_id"], "project ID")
        after = body.get("after", 0)
        if isinstance(after, bool) or not isinstance(after, int) or after < 0:
            raise HubError(400, "invalid_cursor", "Invalid mailbox cursor.")
        limit = _positive_int(body.get("limit", 32), "page limit", maximum=MAX_PAGE)
        now = _now()
        with self.transaction() as connection:
            self._membership(connection, project_id, principal)
            self._expire_messages(connection, now)
            rows = connection.execute(
                """SELECT sequence, envelope FROM messages
                   WHERE project_id = ? AND recipient = ? AND state = 'pending'
                     AND sequence > ?
                   ORDER BY sequence LIMIT ?""",
                (project_id, principal, after, limit),
            ).fetchall()
            sequences = [int(row["sequence"]) for row in rows]
            if sequences:
                connection.executemany(
                    "UPDATE messages SET delivered_at = ? WHERE sequence = ?",
                    ((now, sequence) for sequence in sequences),
                )
        messages = [
            {
                "sequence": int(row["sequence"]),
                "envelope": json.loads(bytes(row["envelope"])),
            }
            for row in rows
        ]
        return {
            "project_id": project_id,
            "messages": messages,
            "next_cursor": sequences[-1] if sequences else after,
            "has_more": len(messages) == limit,
        }

    def acknowledge(self, principal: str, body: Mapping[str, Any]) -> dict[str, Any]:
        if set(body) != {"project_id", "message_ids"}:
            raise HubError(400, "invalid_ack", "Invalid mailbox acknowledgement.")
        project_id = _identifier(body["project_id"], "project ID")
        message_ids = body["message_ids"]
        if (
            not isinstance(message_ids, list)
            or not message_ids
            or len(message_ids) > MAX_PAGE
        ):
            raise HubError(400, "invalid_ack", "Invalid acknowledgement message IDs.")
        for message_id in message_ids:
            _identifier(message_id, "message ID")
        if len(set(message_ids)) != len(message_ids):
            raise HubError(400, "invalid_ack", "Invalid acknowledgement message IDs.")
        now, acknowledged = _now(), []
        with self.transaction() as connection:
            self._membership(connection, project_id, principal)
            for message_id in message_ids:
                row = connection.execute(
                    """SELECT state FROM messages
                       WHERE message_id = ? AND project_id = ? AND recipient = ?""",
                    (message_id, project_id, principal),
                ).fetchone()
                if row is None:
                    raise HubError(
                        404, "message_not_found", "Mailbox message was not found."
                    )
                if row["state"] == "expired":
                    raise HubError(
                        410, "message_expired", "Mailbox message has expired."
                    )
                if row["state"] == "pending":
                    connection.execute(
                        """UPDATE messages
                           SET state = 'acked', envelope = NULL, acked_at = ?
                           WHERE message_id = ?""",
                        (now, message_id),
                    )
                    acknowledged.append(message_id)
            if acknowledged:
                self._audit(
                    connection,
                    "messages-acknowledged",
                    {
                        "project_id": project_id,
                        "recipient": principal,
                        "message_ids": sorted(acknowledged),
                    },
                )
        return {
            "project_id": project_id,
            "acknowledged": sorted(acknowledged),
            "already_acknowledged": sorted(set(message_ids) - set(acknowledged)),
        }

    def endpoint_status(
        self, principal: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        if set(body) != {"project_id"}:
            raise HubError(400, "invalid_status", "Invalid status request.")
        project_id = _identifier(body["project_id"], "project ID")
        with closing(self._connect()) as connection:
            membership = self._membership(connection, project_id, principal)
            counts = connection.execute(
                """SELECT state, COUNT(*) AS count FROM messages
                   WHERE project_id = ? AND recipient = ? GROUP BY state""",
                (project_id, principal),
            ).fetchall()
        return {
            "project_id": project_id,
            "principal": principal,
            "role": membership["role"],
            "mailbox": {row["state"]: int(row["count"]) for row in counts},
            "server_principal": self.server_principal,
        }

    def server_status(self) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            count_queries = {
                "teams": "SELECT COUNT(*) AS count FROM teams",
                "projects": "SELECT COUNT(*) AS count FROM projects",
                "endpoints": "SELECT COUNT(*) AS count FROM endpoints",
                "memberships": "SELECT COUNT(*) AS count FROM memberships",
            }
            counts = {
                table: int(connection.execute(query).fetchone()["count"])
                for table, query in count_queries.items()
            }
            message_counts = {
                row["state"]: int(row["count"])
                for row in connection.execute(
                    "SELECT state, COUNT(*) AS count FROM messages GROUP BY state"
                ).fetchall()
            }
        return {
            "format": HUB_FORMAT,
            "server_principal": self.server_principal,
            "counts": counts,
            "messages": message_counts,
            "database": str(self.database),
        }

    def set_endpoint_status(self, principal: str, status: str) -> dict[str, Any]:
        principal = _principal(principal)
        if status not in {"active", "disabled"}:
            raise HubError(400, "invalid_endpoint_status", "Invalid endpoint status.")
        with self.transaction() as connection:
            endpoint = connection.execute(
                "SELECT status, label FROM endpoints WHERE principal = ?", (principal,)
            ).fetchone()
            if endpoint is None:
                raise HubError(404, "endpoint_not_found", "Endpoint does not exist.")
            previous = str(endpoint["status"])
            connection.execute(
                "UPDATE endpoints SET status = ? WHERE principal = ?",
                (status, principal),
            )
            if previous != status:
                self._audit(
                    connection,
                    "endpoint-status-changed",
                    {"principal": principal, "previous": previous, "status": status},
                )
        return {
            "principal": principal,
            "label": endpoint["label"],
            "previous": previous,
            "status": status,
        }

    def purge(self) -> dict[str, int]:
        now = _now()
        with self.transaction() as connection:
            expired = self._expire_messages(connection, now)
            nonce_count = connection.execute(
                "DELETE FROM request_nonces WHERE used_at < ?",
                (now - 2 * REQUEST_WINDOW_SECONDS,),
            ).rowcount
            enrollment_count = connection.execute(
                "DELETE FROM enrollments WHERE expires_at < ? AND used_at IS NULL",
                (now - 24 * 3600,),
            ).rowcount
            receipt_count = connection.execute(
                """DELETE FROM messages
                   WHERE (state = 'acked' AND acked_at < ?)
                      OR (state = 'expired' AND expires_at < ?)""",
                (
                    now - RECEIPT_RETENTION_SECONDS,
                    now - RECEIPT_RETENTION_SECONDS,
                ),
            ).rowcount
        return {
            "expired_messages": expired,
            "deleted_nonces": nonce_count,
            "deleted_enrollments": enrollment_count,
            "deleted_receipts": receipt_count,
        }

    def verify_audit(self) -> dict[str, Any]:
        previous = "0" * 64
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM audit ORDER BY sequence"
            ).fetchall()
        for row in rows:
            try:
                details = json.loads(row["details"])
            except json.JSONDecodeError as error:
                raise HubError(
                    500, "audit_invalid", "Audit details are invalid."
                ) from error
            record = {
                "created_at": int(row["created_at"]),
                "event": row["event"],
                "details": details,
                "previous_digest": previous,
            }
            calculated = _digest(record)
            if row["previous_digest"] != previous or row["digest"] != calculated:
                raise HubError(500, "audit_invalid", "Team Hub audit chain is invalid.")
            previous = calculated
        return {"valid": True, "events": len(rows), "head": previous}

    def signed_response(
        self, path: str, request_nonce: str, result: Mapping[str, Any]
    ) -> dict[str, Any]:
        body = dict(result)
        subject = {
            "action": "team-hub-response",
            "path": path,
            "request_nonce": request_nonce,
            "body_sha256": _digest(body),
        }
        return {
            "format": HUB_FORMAT,
            "result": body,
            "server_identity": create_identity_assertion(self.identity, subject),
        }


class BoundedHubServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, *args: Any, max_workers: int = 32, **kwargs: Any) -> None:
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        self.rate_limiter = HubRateLimiter()
        super().__init__(*args, **kwargs)

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._worker_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._worker_slots.release()
            raise

    def get_request(self) -> tuple[socket.socket, Any]:
        request_socket, client_address = super().get_request()
        request_socket.settimeout(REQUEST_TIMEOUT_SECONDS)
        return request_socket, client_address

    def process_request_thread(
        self, request: socket.socket, client_address: Any
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


class HubHandler(BaseHTTPRequestHandler):
    server_version = "SessionBridgeTeamHub/0.1"
    protocol_version = "HTTP/1.1"

    @property
    def store(self) -> HubStore:
        return self.server.store  # type: ignore[attr-defined]

    def setup(self) -> None:
        super().setup()
        # Hard total-connection deadline so a slow/dribbling client cannot hold a
        # worker slot past the per-recv timeout by trickling one byte at a time.
        self._deadline = threading.Timer(
            CONNECTION_DEADLINE_SECONDS, self._force_close
        )
        self._deadline.daemon = True
        self._deadline.start()

    def finish(self) -> None:
        deadline = getattr(self, "_deadline", None)
        if deadline is not None:
            deadline.cancel()
        super().finish()

    def _force_close(self) -> None:
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def log_message(self, format: str, *args: Any) -> None:
        # Never log bodies or authentication objects.
        sys.stderr.write(
            "%s - - [%s] %s\n"
            % (self.address_string(), self.log_date_time_string(), format % args)
        )

    def _send(self, status: int, value: Mapping[str, Any]) -> None:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        # Close after every response: one request per connection releases the
        # worker slot promptly and discards any undrained body, preventing a
        # keep-alive request-smuggling/desync behind a pooling reverse proxy.
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()
        self.wfile.write(raw)

    def _error(self, error: HubError) -> None:
        self._send(
            error.status,
            {"error": {"code": error.code, "message": str(error)}},
        )

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._send(
                200,
                {
                    "status": "ok",
                    "format": HUB_FORMAT,
                    "server_principal": self.store.server_principal,
                },
            )
            return
        self._send(404, {"error": {"code": "not_found", "message": "Not found."}})

    def _client_ip(self) -> str:
        raw = str(self.client_address[0])
        # Behind the documented reverse proxy every request shares the proxy IP,
        # collapsing per-IP limits into one global bucket.  Only when explicitly
        # told the proxy is trusted, key on the forwarded client address instead.
        if os.environ.get("SESSION_BRIDGE_HUB_TRUSTED_PROXY") == "1":
            forwarded = self.headers.get("X-Forwarded-For", "")
            candidate = forwarded.split(",")[0].strip()
            if candidate:
                return candidate[:64]
        return raw

    def do_POST(self) -> None:  # noqa: N802
        response_nonce: str | None = None
        try:
            client_key = f"ip:{self._client_ip()}"
            if not self.server.rate_limiter.allow(client_key, 240, 60):  # type: ignore[attr-defined]
                raise HubError(429, "rate_limited", "Too many requests.")
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
            if content_type != "application/json":
                raise HubError(
                    415,
                    "unsupported_media_type",
                    "Content-Type must be application/json.",
                )
            length_text = self.headers.get("Content-Length")
            if length_text is None:
                raise HubError(411, "length_required", "Content-Length is required.")
            # Reject non-canonical values (int() accepts "1_000", "+10", " 10 ")
            # a strict fronting proxy would parse differently, avoiding a
            # request-length disagreement.
            if not re.fullmatch(r"[0-9]+", length_text):
                raise HubError(400, "invalid_length", "Invalid Content-Length.")
            length = int(length_text)
            if length < 0 or length > MAX_HTTP_BODY:
                raise HubError(413, "request_too_large", "Request body is too large.")
            request = _json_loads(self.rfile.read(length))
            if self.path == "/v1/enroll":
                if not self.server.rate_limiter.allow(  # type: ignore[attr-defined]
                    client_key + ":enroll", 20, 60
                ):
                    raise HubError(429, "rate_limited", "Too many enrollment requests.")
                result = self.store.redeem_enrollment(request)
                nonce = secrets.token_hex(16)
                self._send(200, self.store.signed_response(self.path, nonce, result))
                return
            routes = {
                "/v1/directory": self.store.directory,
                "/v1/mailbox/push": self.store.push,
                "/v1/mailbox/pull": self.store.pull,
                "/v1/mailbox/ack": self.store.acknowledge,
                "/v1/status": self.store.endpoint_status,
            }
            operation = routes.get(self.path)
            if operation is None:
                raise HubError(404, "not_found", "Not found.")
            if isinstance(request, Mapping):
                auth = request.get("auth")
                if isinstance(auth, Mapping):
                    candidate = auth.get("nonce")
                    if isinstance(candidate, str) and NONCE.fullmatch(candidate):
                        response_nonce = candidate
            principal, body, nonce = self.store.authenticate(self.path, request)
            response_nonce = nonce
            if not self.server.rate_limiter.allow(  # type: ignore[attr-defined]
                f"principal:{principal}", 300, 60
            ):
                raise HubError(429, "rate_limited", "Too many endpoint requests.")
            result = operation(principal, body)
            self._send(200, self.store.signed_response(self.path, nonce, result))
        except HubError as error:
            if response_nonce is None:
                self._error(error)
            else:
                self._send(
                    error.status,
                    self.store.signed_response(
                        self.path,
                        response_nonce,
                        {"error": {"code": error.code, "message": str(error)}},
                    ),
                )
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as error:
            # Record only the exception class; request bodies and credentials never
            # belong in server logs.
            self.log_error(
                "Unhandled Team Hub request failure (%s)", type(error).__name__
            )
            self._send(
                500,
                {"error": {"code": "internal_error", "message": "Internal error."}},
            )


def _default_data_dir() -> Path:
    configured = os.environ.get("SESSION_BRIDGE_HUB_HOME")
    return (
        Path(configured).expanduser()
        if configured
        else Path.home() / ".session-bridge-hub"
    )


def _json_print(value: Mapping[str, Any]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def command_init(args: argparse.Namespace) -> None:
    _json_print(HubStore(args.data_dir).initialize(args.team, args.project))


def command_enrollment(args: argparse.Namespace) -> None:
    store = HubStore(args.data_dir)
    project_id = args.project_id
    if project_id is None:
        if not args.team or not args.project:
            raise HubError(
                400,
                "project_required",
                "Provide --project-id or both --team and --project.",
            )
        project_id = store.resolve_project(args.team, args.project)
    if not args.server_url:
        raise HubError(400, "server_url_required", "Provide --server-url.")
    _json_print(
        store.create_enrollment(
            project_id,
            args.label,
            args.role,
            args.server_url,
            args.expires_seconds,
        )
    )


def command_status(args: argparse.Namespace) -> None:
    _json_print(HubStore(args.data_dir).server_status())


def command_verify(args: argparse.Namespace) -> None:
    _json_print(HubStore(args.data_dir).verify_audit())


def command_purge(args: argparse.Namespace) -> None:
    _json_print(HubStore(args.data_dir).purge())


def command_endpoint(args: argparse.Namespace) -> None:
    _json_print(
        HubStore(args.data_dir).set_endpoint_status(args.principal, args.status)
    )


def command_serve(args: argparse.Namespace) -> None:
    if (
        args.bind not in {"127.0.0.1", "::1", "localhost"}
        and not (args.cert and args.key)
        and not args.allow_insecure_http
    ):
        raise SystemExit(
            "Refusing non-loopback plaintext HTTP. Configure --cert/--key, bind to "
            "loopback behind an HTTPS reverse proxy, or explicitly pass "
            "--allow-insecure-http only on a trusted private network."
        )
    store = HubStore(args.data_dir)
    bootstrap = None
    if bool(args.bootstrap_team) != bool(args.bootstrap_project):
        raise SystemExit(
            "Both --bootstrap-team and --bootstrap-project are required together."
        )
    if args.bootstrap_team:
        bootstrap = store.initialize(args.bootstrap_team, args.bootstrap_project)
    server = BoundedHubServer((args.bind, args.port), HubHandler)
    server.store = store  # type: ignore[attr-defined]
    if bool(args.cert) != bool(args.key):
        raise SystemExit("Both --cert and --key are required for TLS.")
    if args.cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(args.cert, args.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    _json_print(
        {
            "ready": True,
            "bind": args.bind,
            "port": server.server_address[1],
            "tls": bool(args.cert),
            "server_principal": store.server_principal,
            "bootstrap": bootstrap,
        }
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir", type=Path, default=_default_data_dir(), help="Hub state root."
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.5.0")
    commands = parser.add_subparsers(dest="command", required=True)

    initialize = commands.add_parser("init", help="Create a team and project.")
    initialize.add_argument("--team", required=True)
    initialize.add_argument("--project", required=True)
    initialize.set_defaults(handler=command_init)

    enrollment = commands.add_parser(
        "enrollment", help="Create one short-lived endpoint enrollment code."
    )
    enrollment.add_argument("--project-id")
    enrollment.add_argument("--team")
    enrollment.add_argument("--project")
    enrollment.add_argument("--label", required=True)
    enrollment.add_argument(
        "--role", choices=("member", "project-agent", "admin"), default="member"
    )
    enrollment.add_argument(
        "--server-url", default=os.environ.get("SESSION_BRIDGE_HUB_PUBLIC_URL")
    )
    enrollment.add_argument("--expires-seconds", type=int, default=3600)
    enrollment.set_defaults(handler=command_enrollment)

    serve = commands.add_parser("serve", help="Run the Team Hub HTTP service.")
    serve.add_argument("--bind", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    serve.add_argument("--cert")
    serve.add_argument("--key")
    serve.add_argument("--allow-insecure-http", action="store_true")
    serve.add_argument("--bootstrap-team")
    serve.add_argument("--bootstrap-project")
    serve.set_defaults(handler=command_serve)

    status = commands.add_parser("status", help="Show local hub state counts.")
    status.set_defaults(handler=command_status)
    verify = commands.add_parser("verify", help="Verify the hub audit chain.")
    verify.set_defaults(handler=command_verify)
    purge = commands.add_parser("purge", help="Expire payloads and stale metadata.")
    purge.set_defaults(handler=command_purge)
    endpoint = commands.add_parser(
        "endpoint", help="Enable or disable one enrolled cryptographic endpoint."
    )
    endpoint.add_argument("--principal", required=True)
    endpoint.add_argument("--status", choices=("active", "disabled"), required=True)
    endpoint.set_defaults(handler=command_endpoint)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        args.handler(args)
    except HubError as error:
        print(json.dumps({"error": {"code": error.code, "message": str(error)}}))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
