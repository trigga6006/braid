"""Endpoint connector for the self-hosted asynchronous Braid Team Hub."""

from __future__ import annotations

import argparse
import base64
import contextlib
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import sys
import threading
import time
from typing import Any, Iterator, Mapping
from urllib import error, request

import context_exchange as exchange
from context_model import canonical_json as canonical_context_json
from context_security import (
    SecurityError,
    canonical_bytes,
    create_identity_assertion,
    identity_principal,
    load_or_create_identity,
    strict_json_loads,
    verify_identity_assertion,
)
from context_store import ContextLedger
import incident_workflow as incident
import network_bridge as bridge
import team_hub as hub


CONNECTOR_FORMAT = "braid-team-connector/v1"
MAILBOX_IDENTITY_FORMAT = "braid-mailbox-identity/v1"
MAX_RESPONSE_BYTES = 2_000_000
DEFAULT_SYNC_INTERVAL = 12 * 3600
DEFAULT_RETRY_MIN_SECONDS = 5
DEFAULT_RETRY_MAX_SECONDS = 300
MAX_SYNC_PAGES = 100


class ConnectorError(ValueError):
    """Safe endpoint-side failure."""


class TransientConnectorError(ConnectorError):
    """Connectivity or server-pressure failure that an always-on loop may retry."""


class PermanentRejectionError(ConnectorError):
    """A definitive server rejection that retrying cannot fix (drop, don't retry)."""


# Hub error codes for a push that retrying the exact request cannot fix.  Keyed
# by authenticated error CODE, not HTTP status, because 403/409 also cover
# reversible cases (endpoint_not_active can be reactivated, replayed_request
# succeeds with a fresh nonce) that must stay queued.
PERMANENT_HUB_CODES = frozenset(
    {
        "invalid_envelope",
        "invalid_envelope_time",
        "invalid_push",
        "envelope_too_large",
        "not_a_project_member",
        "message_id_conflict",
    }
)


@dataclass(frozen=True)
class MailboxIdentity:
    public_key: bytes
    private_key: bytes


def connector_home(explicit: Path | None = None) -> Path:
    if explicit is not None:
        return explicit.expanduser().resolve()
    return (
        Path(os.environ.get("BRAID_HOME", Path.home() / ".braid"))
        .expanduser()
        .resolve()
    )


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64d(value: Any, maximum: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum * 2:
        raise ConnectorError("Invalid encoded value.")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (TypeError, ValueError) as error:
        raise ConnectorError("Invalid encoded value.") from error
    if len(decoded) > maximum:
        raise ConnectorError("Encoded value exceeds the safety limit.")
    return decoded


def _read_json(path: Path, maximum: int = MAX_RESPONSE_BYTES) -> dict[str, Any]:
    try:
        with open(path, "rb") as handle:
            raw = handle.read(maximum + 1)
    except OSError as error:
        raise ConnectorError(f"Unable to read {path}.") from error
    if len(raw) > maximum:
        raise ConnectorError(f"File exceeds the safety limit: {path}")
    try:
        value = strict_json_loads(raw)
    except SecurityError as error:
        raise ConnectorError(f"Invalid JSON file: {path}") from error
    if not isinstance(value, dict):
        raise ConnectorError(f"JSON file must contain an object: {path}")
    return value


def _safe_alias(value: str) -> str:
    try:
        return hub._identifier(value, "project alias")
    except hub.HubError as error:
        raise ConnectorError(str(error)) from error


@contextlib.contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "a+b")
    locked = False
    try:
        if os.name == "nt":
            import msvcrt

            if handle.seek(0, os.SEEK_END) == 0:
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
            if locked and os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            elif locked:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def _mailbox_identity_path(home: Path) -> Path:
    return home / "mailbox-identity.json"


def load_or_create_mailbox_identity(home: Path) -> MailboxIdentity:
    path = _mailbox_identity_path(home)
    with _file_lock(path.with_name(path.name + ".lock")):
        if path.exists():
            value = bridge.load_json(path)
            if (
                set(value) != {"format", "public_key", "private_key"}
                or value.get("format") != MAILBOX_IDENTITY_FORMAT
            ):
                raise ConnectorError("Mailbox identity file is invalid.")
            public = _b64d(value["public_key"], 64)
            try:
                private = bridge.unprotect_secret(value["private_key"])
            except (SystemExit, ValueError) as error:
                raise ConnectorError("Mailbox identity cannot be unlocked.") from error
            if len(public) != 32 or len(private) != 32:
                raise ConnectorError("Mailbox identity key length is invalid.")
            _, generated_public = _public_from_private(private)
            if generated_public != public:
                raise ConnectorError("Mailbox identity keys do not match.")
            return MailboxIdentity(public, private)
        private, public = bridge.generate_exchange_keypair()
        bridge.save_json(
            path,
            {
                "format": MAILBOX_IDENTITY_FORMAT,
                "public_key": _b64e(public),
                "private_key": bridge.protect_secret(private),
            },
        )
        return MailboxIdentity(public, private)


def _public_from_private(private_raw: bytes) -> tuple[Any, bytes]:
    _, _, serialization, _, x25519, _, _, _ = bridge.crypto_imports()
    private = x25519.X25519PrivateKey.from_private_bytes(private_raw)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, public


def _mailbox_key(
    private_raw: bytes,
    peer_public_raw: bytes,
    project_id: str,
    sender: str,
    recipient: str,
) -> bytes:
    _, hashes, _, _, x25519, _, HKDF, _ = bridge.crypto_imports()
    try:
        private = x25519.X25519PrivateKey.from_private_bytes(private_raw)
        public = x25519.X25519PublicKey.from_public_bytes(peer_public_raw)
        shared = private.exchange(public)
    except ValueError as error:
        raise ConnectorError("Mailbox exchange key is invalid.") from error
    salt = hashlib.sha256(f"{project_id}|{sender}|{recipient}".encode("utf-8")).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"braid/team-mailbox/v1",
    ).derive(shared)


def seal_context_pack(
    bundle: Mapping[str, Any],
    *,
    project_id: str,
    sender: str,
    recipient: str,
    recipient_mailbox_key: bytes,
    ttl_seconds: int = hub.DEFAULT_MESSAGE_TTL_SECONDS,
) -> dict[str, Any]:
    try:
        bridge.validate_disclosure_bundle(dict(bundle), recipient)
    except ValueError as error:
        raise ConnectorError(str(error)) from error
    inner_expiry = int(bundle["export"]["expires_at"])
    return seal_mailbox_payload(
        bundle,
        kind="context-pack",
        project_id=project_id,
        sender=sender,
        recipient=recipient,
        recipient_mailbox_key=recipient_mailbox_key,
        ttl_seconds=ttl_seconds,
        inner_expires_at=inner_expiry,
    )


def seal_mailbox_payload(
    payload: Mapping[str, Any],
    *,
    kind: str,
    project_id: str,
    sender: str,
    recipient: str,
    recipient_mailbox_key: bytes,
    ttl_seconds: int = hub.DEFAULT_MESSAGE_TTL_SECONDS,
    inner_expires_at: int | None = None,
) -> dict[str, Any]:
    """Encrypt one strict application payload to an enrolled endpoint."""
    if kind not in {"context-pack", "coordination-note"}:
        raise ConnectorError("Mailbox payload kind is invalid.")
    if ttl_seconds < 1 or ttl_seconds > hub.MAX_MESSAGE_TTL_SECONDS:
        raise ConnectorError("Mailbox message lifetime is invalid.")
    private, ephemeral_public = bridge.generate_exchange_keypair()
    key = _mailbox_key(private, recipient_mailbox_key, project_id, sender, recipient)
    now = int(time.time())
    message_id = "msg_" + secrets.token_hex(16)
    expiry = now + ttl_seconds
    if inner_expires_at is not None:
        expiry = min(expiry, inner_expires_at)
    header = {
        "format": hub.ENVELOPE_FORMAT,
        "message_id": message_id,
        "project_id": project_id,
        "sender": sender,
        "recipient": recipient,
        "kind": kind,
        "created_at": now,
        "expires_at": expiry,
        "ephemeral_public_key": _b64e(ephemeral_public),
    }
    if header["expires_at"] <= now:
        raise ConnectorError("Mailbox payload has already expired.")
    plaintext = canonical_bytes(dict(payload))
    if len(plaintext) > hub.MAX_ENVELOPE_BYTES - 4096:
        raise ConnectorError("Mailbox payload is too large for a Team Hub envelope.")
    _, _, _, _, _, ChaCha20Poly1305, _, _ = bridge.crypto_imports()
    nonce = secrets.token_bytes(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(
        nonce, plaintext, canonical_bytes(header)
    )
    return {
        **header,
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
    }


def open_context_pack(
    envelope: Mapping[str, Any],
    *,
    mailbox_identity: MailboxIdentity,
    expected_project: str,
    expected_recipient: str,
) -> dict[str, Any]:
    bundle = open_mailbox_payload(
        envelope,
        mailbox_identity=mailbox_identity,
        expected_project=expected_project,
        expected_recipient=expected_recipient,
        expected_kind="context-pack",
    )
    try:
        bridge.validate_disclosure_bundle(bundle, expected_recipient)
    except ValueError as error:
        raise ConnectorError(str(error)) from error
    return bundle


def open_mailbox_payload(
    envelope: Mapping[str, Any],
    *,
    mailbox_identity: MailboxIdentity,
    expected_project: str,
    expected_recipient: str,
    expected_kind: str,
) -> dict[str, Any]:
    """Authenticate and decrypt one mailbox payload without interpreting it."""
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
    if set(envelope) != required or envelope.get("format") != hub.ENVELOPE_FORMAT:
        raise ConnectorError("Invalid mailbox envelope.")
    if expected_kind not in {"context-pack", "coordination-note"}:
        raise ConnectorError("Expected mailbox payload kind is invalid.")
    if envelope.get("kind") != expected_kind:
        raise ConnectorError("Mailbox envelope kind is unexpected.")
    if envelope.get("project_id") != expected_project:
        raise ConnectorError("Mailbox envelope is for another project.")
    if envelope.get("recipient") != expected_recipient:
        raise ConnectorError("Mailbox envelope is for another endpoint.")
    try:
        hub._identifier(envelope.get("message_id"), "mailbox message ID")
    except hub.HubError as error:
        raise ConnectorError(str(error)) from error
    created_at = envelope.get("created_at")
    expires_at = envelope.get("expires_at")
    if (
        isinstance(created_at, bool)
        or not isinstance(created_at, int)
        or created_at < 1
        or created_at > int(time.time()) + hub.REQUEST_WINDOW_SECONDS
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or expires_at <= created_at
        or expires_at > created_at + hub.MAX_MESSAGE_TTL_SECONDS
        or expires_at <= int(time.time())
    ):
        raise ConnectorError("Mailbox envelope timing is invalid or expired.")
    sender = envelope.get("sender")
    try:
        sender = hub._principal(sender, "mailbox envelope sender")
    except hub.HubError as error:
        raise ConnectorError(str(error)) from error
    ephemeral_public = _b64d(envelope.get("ephemeral_public_key"), 64)
    nonce = _b64d(envelope.get("nonce"), 32)
    ciphertext = _b64d(envelope.get("ciphertext"), hub.MAX_ENVELOPE_BYTES)
    if len(ephemeral_public) != 32 or len(nonce) != 12 or len(ciphertext) < 17:
        raise ConnectorError("Mailbox envelope cryptography is invalid.")
    header = {key: envelope[key] for key in required - {"nonce", "ciphertext"}}
    key = _mailbox_key(
        mailbox_identity.private_key,
        ephemeral_public,
        expected_project,
        sender,
        expected_recipient,
    )
    _, _, _, _, _, ChaCha20Poly1305, _, _ = bridge.crypto_imports()
    from cryptography.exceptions import InvalidTag

    try:
        plaintext = ChaCha20Poly1305(key).decrypt(
            nonce, ciphertext, canonical_bytes(header)
        )
    except InvalidTag as error:
        raise ConnectorError("Mailbox envelope authentication failed.") from error
    try:
        payload = strict_json_loads(plaintext)
    except SecurityError as error:
        raise ConnectorError("Decrypted mailbox payload is invalid.") from error
    if not isinstance(payload, dict):
        raise ConnectorError("Decrypted mailbox payload must be an object.")
    return payload


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class HubClient:
    def __init__(
        self, server_url: str, server_principal: str, timeout: int = 30
    ) -> None:
        try:
            self.server_url = hub._validate_server_url(server_url)
        except hub.HubError as error:
            raise ConnectorError(str(error)) from error
        self.server_principal = server_principal
        self.timeout = timeout
        self._opener = request.build_opener(_NoRedirect())

    def _post(
        self,
        path: str,
        value: Mapping[str, Any],
        *,
        request_nonce: str | None = None,
    ) -> dict[str, Any]:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        target = self.server_url + path
        outgoing = request.Request(
            target,
            data=raw,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with self._opener.open(outgoing, timeout=self.timeout) as response:
                if response.geturl() != target:
                    raise ConnectorError("Team Hub redirected the request.")
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ConnectorError("Team Hub response is too large.")
        except error.HTTPError as failure:
            raw_error = failure.read(64_001)
            code = ""
            signed_error = False
            try:
                parsed = strict_json_loads(raw_error)
                if request_nonce is not None and isinstance(parsed, Mapping):
                    result = self._verify_response(
                        path, parsed, request_nonce=request_nonce
                    )
                    error_body = result["error"]
                    signed_error = True
                else:
                    error_body = parsed["error"]
                message = error_body["message"]
                code = str(error_body.get("code", ""))
                if not isinstance(message, str):
                    raise TypeError("error message is not text")
            except (ConnectorError, SecurityError, KeyError, TypeError):
                message = f"Team Hub returned HTTP {failure.code}."
            if failure.code in {408, 425, 429} or failure.code >= 500:
                failure_type = TransientConnectorError
            elif signed_error and code in PERMANENT_HUB_CODES:
                # Definitive, message-specific rejection: retrying the exact
                # request cannot succeed.  Classified by error code so reversible
                # 403/409 cases (endpoint_not_active, replayed_request) stay
                # queued instead of being dropped.
                failure_type = PermanentRejectionError
            else:
                failure_type = ConnectorError
            raise failure_type(str(message)) from failure
        except error.URLError as failure:
            raise TransientConnectorError(
                f"Unable to reach Team Hub: {failure.reason}"
            ) from failure
        try:
            parsed = strict_json_loads(body)
        except SecurityError as failure:
            raise ConnectorError("Team Hub returned invalid JSON.") from failure
        if not isinstance(parsed, dict):
            raise ConnectorError("Team Hub returned an invalid response.")
        return parsed

    def _verify_response(
        self,
        path: str,
        response: Mapping[str, Any],
        *,
        request_nonce: str | None,
    ) -> dict[str, Any]:
        if (
            set(response) != {"format", "result", "server_identity"}
            or response.get("format") != hub.HUB_FORMAT
        ):
            raise ConnectorError("Team Hub response has an invalid shape.")
        result, assertion = response["result"], response["server_identity"]
        if not isinstance(result, dict) or not isinstance(assertion, Mapping):
            raise ConnectorError("Team Hub response has an invalid shape.")
        subject = assertion.get("subject")
        if not isinstance(subject, Mapping):
            raise ConnectorError("Team Hub response identity is invalid.")
        nonce = subject.get("request_nonce")
        if not isinstance(nonce, str) or not hub.NONCE.fullmatch(nonce):
            raise ConnectorError("Team Hub response nonce is invalid.")
        if request_nonce is not None and nonce != request_nonce:
            raise ConnectorError("Team Hub response is bound to another request.")
        expected_subject = {
            "action": "team-hub-response",
            "path": path,
            "request_nonce": nonce,
            "body_sha256": hashlib.sha256(canonical_bytes(result)).hexdigest(),
        }
        try:
            principal = verify_identity_assertion(assertion, expected_subject)
        except SecurityError as failure:
            raise ConnectorError("Team Hub response signature is invalid.") from failure
        if principal != self.server_principal:
            raise ConnectorError("Team Hub server identity changed.")
        return result

    def enroll(self, request_body: Mapping[str, Any]) -> dict[str, Any]:
        return self._verify_response(
            "/v1/enroll",
            self._post("/v1/enroll", request_body),
            request_nonce=None,
        )

    def authenticated(
        self,
        path: str,
        body: Mapping[str, Any],
        identity_path: Path,
    ) -> dict[str, Any]:
        identity = load_or_create_identity(identity_path)
        timestamp, nonce = int(time.time()), secrets.token_hex(16)
        subject = {
            "action": "team-hub-request",
            "path": path,
            "body_sha256": hashlib.sha256(canonical_bytes(dict(body))).hexdigest(),
            "timestamp": timestamp,
            "nonce": nonce,
        }
        wrapper = {
            "format": hub.REQUEST_FORMAT,
            "body": dict(body),
            "auth": {
                "timestamp": timestamp,
                "nonce": nonce,
                "identity": create_identity_assertion(identity, subject),
            },
        }
        return self._verify_response(
            path,
            self._post(path, wrapper, request_nonce=nonce),
            request_nonce=nonce,
        )


class TeamConnector:
    def __init__(self, home: Path | None = None) -> None:
        self.home = connector_home(home)
        self.home.mkdir(parents=True, exist_ok=True)
        self.projects = self.home / "team-projects"
        self.projects.mkdir(parents=True, exist_ok=True)
        self.identity_path = self.home / "recipient-identity.json"
        self.mailbox_identity = load_or_create_mailbox_identity(self.home)

    def config_path(self, alias: str) -> Path:
        return self.projects / f"{_safe_alias(alias)}.json"

    def lock_path(self, alias: str) -> Path:
        return self.projects / f"{_safe_alias(alias)}.lock"

    def exchange_state_path(self, alias: str, direction: str, request_id: str) -> Path:
        if direction not in {"inbound", "outbound"}:
            raise ConnectorError("Exchange direction is invalid.")
        try:
            request_id = hub._identifier(request_id, "request ID")
        except hub.HubError as error:
            raise ConnectorError(str(error)) from error
        return (
            self.home
            / "team-exchanges"
            / _safe_alias(alias)
            / direction
            / f"{request_id}.json"
        )

    def load_config(self, alias: str) -> dict[str, Any]:
        path = self.config_path(alias)
        if not path.exists():
            raise ConnectorError(f"Team project is not enrolled: {alias}")
        value = bridge.load_json(path)
        required = {
            "format",
            "alias",
            "server_url",
            "server_principal",
            "project_id",
            "principal",
            "mailbox_public_key",
            "label",
            "role",
            "cursor",
            "enrolled_at",
            "published",
            "trusted_peers",
        }
        if "published" not in value:
            value["published"] = {}
        if "trusted_peers" not in value:
            value["trusted_peers"] = {}
        if (
            set(value) != required
            or value.get("format") != CONNECTOR_FORMAT
            or not isinstance(value["published"], dict)
            or not isinstance(value["trusted_peers"], dict)
        ):
            raise ConnectorError("Team project configuration is invalid.")
        if value["alias"] != _safe_alias(alias):
            raise ConnectorError("Team project alias is invalid.")
        try:
            server_url = hub._validate_server_url(value["server_url"])
            hub._principal(value["server_principal"], "server principal")
            hub._identifier(value["project_id"], "project ID")
            local_principal = hub._principal(value["principal"], "local principal")
        except hub.HubError as error:
            raise ConnectorError(str(error)) from error
        if server_url != value["server_url"]:
            raise ConnectorError("Team project server URL is not canonical.")
        if value["role"] not in {"member", "project-agent", "admin"}:
            raise ConnectorError("Team project role is invalid.")
        cursor = value["cursor"]
        if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0:
            raise ConnectorError("Team project cursor is invalid.")
        if _b64d(value["mailbox_public_key"], 64) != self.mailbox_identity.public_key:
            raise ConnectorError("Team project mailbox identity changed.")
        if (
            identity_principal(load_or_create_identity(self.identity_path))
            != local_principal
        ):
            raise ConnectorError("Team project recipient identity changed.")
        for principal, record in value["trusted_peers"].items():
            try:
                hub._principal(principal, "trusted peer principal")
            except hub.HubError as error:
                raise ConnectorError(str(error)) from error
            if (
                not isinstance(record, dict)
                or set(record)
                != {
                    "mailbox_public_key",
                    "mailbox_key_sha256",
                    "binding_sha256",
                    "role",
                    "trusted_at",
                }
                or record["role"] not in {"member", "project-agent", "admin"}
                or not isinstance(record["trusted_at"], int)
            ):
                raise ConnectorError("Trusted peer record is invalid.")
        return value

    def save_config(self, alias: str, value: Mapping[str, Any]) -> None:
        bridge.save_json(self.config_path(alias), dict(value))

    def client(self, config: Mapping[str, Any]) -> HubClient:
        return HubClient(str(config["server_url"]), str(config["server_principal"]))

    @staticmethod
    def _validate_directory_endpoint(
        endpoint: Mapping[str, Any], config: Mapping[str, Any]
    ) -> dict[str, Any]:
        required = {
            "principal",
            "mailbox_public_key",
            "mailbox_binding",
            "label",
            "role",
        }
        if set(endpoint) != required:
            raise ConnectorError("Team Hub directory endpoint has an invalid shape.")
        try:
            principal = hub._principal(endpoint["principal"], "directory principal")
            label = hub._label(endpoint["label"], "directory label")
        except hub.HubError as error:
            raise ConnectorError(str(error)) from error
        role = endpoint["role"]
        if role not in {"member", "project-agent", "admin"}:
            raise ConnectorError("Team Hub directory endpoint role is invalid.")
        mailbox_public_key = str(endpoint["mailbox_public_key"])
        if len(_b64d(mailbox_public_key, 64)) != 32:
            raise ConnectorError("Team Hub directory mailbox key is invalid.")
        mailbox_binding = endpoint["mailbox_binding"]
        if not isinstance(mailbox_binding, Mapping):
            raise ConnectorError("Team Hub directory mailbox binding is invalid.")
        binding_subject = {
            "action": "team-hub-mailbox-binding",
            "project_id": config["project_id"],
            "server_principal": config["server_principal"],
            "mailbox_public_key": mailbox_public_key,
        }
        try:
            binding_principal = verify_identity_assertion(
                mailbox_binding, binding_subject
            )
        except SecurityError as error:
            raise ConnectorError(
                "Team Hub directory mailbox binding is invalid."
            ) from error
        if binding_principal != principal:
            raise ConnectorError(
                "Team Hub directory mailbox binding uses another endpoint identity."
            )
        return {
            "principal": principal,
            "mailbox_public_key": mailbox_public_key,
            "mailbox_binding": dict(mailbox_binding),
            "label": label,
            "role": role,
        }

    @staticmethod
    def _trust_record(endpoint: Mapping[str, Any]) -> dict[str, Any]:
        mailbox_key = _b64d(endpoint["mailbox_public_key"], 64)
        return {
            "mailbox_public_key": endpoint["mailbox_public_key"],
            "mailbox_key_sha256": hashlib.sha256(mailbox_key).hexdigest(),
            "binding_sha256": hashlib.sha256(
                canonical_bytes(dict(endpoint["mailbox_binding"]))
            ).hexdigest(),
            "role": endpoint["role"],
            "trusted_at": int(time.time()),
        }

    @classmethod
    def _trust_status(
        cls, config: Mapping[str, Any], endpoint: Mapping[str, Any]
    ) -> str:
        existing = config["trusted_peers"].get(endpoint["principal"])
        if not isinstance(existing, Mapping):
            return "untrusted"
        expected = cls._trust_record(endpoint)
        stable = set(expected) - {"trusted_at"}
        return (
            "trusted"
            if all(existing.get(key) == expected[key] for key in stable)
            else "changed"
        )

    def _fetch_directory(self, config: Mapping[str, Any]) -> dict[str, Any]:
        result = self.client(config).authenticated(
            "/v1/directory",
            {"project_id": config["project_id"]},
            self.identity_path,
        )
        if set(result) != {"project_id", "endpoints"} or result.get(
            "project_id"
        ) != config.get("project_id"):
            raise ConnectorError("Team Hub directory response is invalid.")
        endpoints = result.get("endpoints")
        if (
            not isinstance(endpoints, list)
            or len(endpoints) > hub.MAX_PROJECT_ENDPOINTS
        ):
            raise ConnectorError("Team Hub directory response is invalid.")
        validated: list[dict[str, Any]] = []
        for endpoint in endpoints:
            if not isinstance(endpoint, Mapping):
                raise ConnectorError("Team Hub directory endpoint is invalid.")
            validated.append(self._validate_directory_endpoint(endpoint, config))
        principals = [endpoint["principal"] for endpoint in validated]
        if len(set(principals)) != len(principals):
            raise ConnectorError("Team Hub directory contains duplicate endpoints.")
        return {"project_id": config["project_id"], "endpoints": validated}

    def enroll(self, alias: str, code_text: str) -> dict[str, Any]:
        alias = _safe_alias(alias)
        try:
            code = hub.decode_enrollment_code(code_text)
        except hub.HubError as error:
            raise ConnectorError(str(error)) from error
        identity = load_or_create_identity(self.identity_path)
        principal = identity_principal(identity)
        mailbox_public_text = _b64e(self.mailbox_identity.public_key)
        secret_digest = hashlib.sha256(str(code["secret"]).encode("ascii")).hexdigest()
        subject = {
            "action": "team-hub-enroll",
            "project_id": code["project_id"],
            "server_principal": code["server_principal"],
            "mailbox_public_key": mailbox_public_text,
            "secret_digest": secret_digest,
            "expires_at": code["expires_at"],
        }
        binding_subject = {
            "action": "team-hub-mailbox-binding",
            "project_id": code["project_id"],
            "server_principal": code["server_principal"],
            "mailbox_public_key": mailbox_public_text,
        }
        result = HubClient(
            str(code["server_url"]), str(code["server_principal"])
        ).enroll(
            {
                "code": code_text,
                "mailbox_public_key": mailbox_public_text,
                "identity": create_identity_assertion(identity, subject),
                "mailbox_binding": create_identity_assertion(identity, binding_subject),
            }
        )
        if result.get("principal") != principal or result.get("project_id") != code.get(
            "project_id"
        ):
            raise ConnectorError(
                "Team Hub enrollment response does not match this endpoint."
            )
        config = {
            "format": CONNECTOR_FORMAT,
            "alias": alias,
            "server_url": code["server_url"],
            "server_principal": code["server_principal"],
            "project_id": code["project_id"],
            "principal": principal,
            "mailbox_public_key": mailbox_public_text,
            "label": result["label"],
            "role": result["role"],
            "cursor": 0,
            "enrolled_at": int(time.time()),
            "published": {},
            "trusted_peers": {},
        }
        existing_path = self.config_path(alias)
        if existing_path.exists():
            existing = self.load_config(alias)
            stable = set(config) - {"enrolled_at"}
            if any(existing[key] != config[key] for key in stable):
                raise ConnectorError("Team project alias is already enrolled.")
            return existing
        self.save_config(alias, config)
        return config

    def directory(self, alias: str) -> dict[str, Any]:
        config = self.load_config(alias)
        result = self._fetch_directory(config)
        return {
            **result,
            "endpoints": [
                {
                    **endpoint,
                    "trust": (
                        "self"
                        if endpoint["principal"] == config["principal"]
                        else self._trust_status(config, endpoint)
                    ),
                }
                for endpoint in result["endpoints"]
            ],
        }

    def trust(self, alias: str, principal: str) -> dict[str, Any]:
        try:
            principal = hub._principal(principal, "trusted peer principal")
        except hub.HubError as error:
            raise ConnectorError(str(error)) from error
        with _file_lock(self.lock_path(alias)):
            config = self.load_config(alias)
            if principal == config["principal"]:
                raise ConnectorError("The local endpoint does not need peer approval.")
            directory = self._fetch_directory(config)
            matches = [
                endpoint
                for endpoint in directory["endpoints"]
                if endpoint["principal"] == principal
            ]
            if len(matches) != 1:
                raise ConnectorError("Peer is not an active project endpoint.")
            endpoint = matches[0]
            record = self._trust_record(endpoint)
            trusted_peers = dict(config["trusted_peers"])
            trusted_peers[principal] = record
            config["trusted_peers"] = trusted_peers
            self.save_config(alias, config)
        return {
            "project": alias,
            "principal": principal,
            "label": endpoint["label"],
            "role": endpoint["role"],
            **record,
        }

    def untrust(self, alias: str, principal: str) -> dict[str, Any]:
        try:
            principal = hub._principal(principal, "trusted peer principal")
        except hub.HubError as error:
            raise ConnectorError(str(error)) from error
        with _file_lock(self.lock_path(alias)):
            config = self.load_config(alias)
            trusted_peers = dict(config["trusted_peers"])
            removed = trusted_peers.pop(principal, None) is not None
            config["trusted_peers"] = trusted_peers
            self.save_config(alias, config)
        return {"project": alias, "principal": principal, "removed": removed}

    def status(self, alias: str) -> dict[str, Any]:
        config = self.load_config(alias)
        remote = self.client(config).authenticated(
            "/v1/status",
            {"project_id": config["project_id"]},
            self.identity_path,
        )
        return {"local": config, "remote": remote}

    def _trusted_endpoint(self, alias: str, principal: str) -> dict[str, Any]:
        try:
            principal = hub._principal(principal, "exchange peer principal")
        except hub.HubError as error:
            raise ConnectorError(str(error)) from error
        directory = self.directory(alias)
        matches = [
            endpoint
            for endpoint in directory.get("endpoints", [])
            if isinstance(endpoint, dict) and endpoint.get("principal") == principal
        ]
        if len(matches) != 1:
            raise ConnectorError("Exchange peer is not an active project endpoint.")
        if matches[0].get("trust") != "trusted":
            raise ConnectorError(
                "Exchange peer is not locally trusted; compare its principal "
                "through a trusted channel and run the trust command first."
            )
        return matches[0]

    def _queue_envelope(
        self,
        alias: str,
        envelope: Mapping[str, Any],
        *,
        request_id: str | None = None,
        exchange_direction: str | None = None,
    ) -> Path:
        outbox = self.home / "team-outbox" / _safe_alias(alias)
        path = outbox / f"{envelope['message_id']}.json"
        record: dict[str, Any] = {"envelope": dict(envelope)}
        if request_id is not None:
            record["request_id"] = request_id
        if exchange_direction is not None:
            record["exchange_direction"] = exchange_direction
        bridge.save_protected_json(path, record)
        return path

    def queue_bundle(
        self, alias: str, bundle_path: Path, ttl_seconds: int
    ) -> dict[str, Any]:
        config = self.load_config(alias)
        bundle = _read_json(bundle_path, hub.MAX_ENVELOPE_BYTES)
        try:
            recipient = str(bundle["export"]["recipient"])
        except (KeyError, TypeError) as error:
            raise ConnectorError("Context Pack recipient is missing.") from error
        endpoint = self._trusted_endpoint(alias, recipient)
        mailbox_public = _b64d(endpoint.get("mailbox_public_key"), 64)
        if len(mailbox_public) != 32:
            raise ConnectorError("Recipient mailbox key is invalid.")
        envelope = seal_context_pack(
            bundle,
            project_id=str(config["project_id"]),
            sender=str(config["principal"]),
            recipient=recipient,
            recipient_mailbox_key=mailbox_public,
            ttl_seconds=ttl_seconds,
        )
        path = self._queue_envelope(alias, envelope)
        return {
            "queued": True,
            "message_id": envelope["message_id"],
            "recipient": recipient,
            "outbox": str(path),
        }

    def queue_request(
        self,
        alias: str,
        *,
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
        ttl_seconds: int = hub.DEFAULT_MESSAGE_TTL_SECONDS,
    ) -> dict[str, Any]:
        """Queue a signed pull request for a bounded semantic context change."""
        config = self.load_config(alias)
        endpoint = self._trusted_endpoint(alias, recipient)
        mailbox_public = _b64d(endpoint.get("mailbox_public_key"), 64)
        identity = load_or_create_identity(self.identity_path)
        try:
            pull_request = exchange.create_request(
                identity,
                project_id=str(config["project_id"]),
                recipient=recipient,
                purpose=purpose,
                question=question,
                kinds=kinds,
                semantic_keys=semantic_keys,
                labels=labels,
                since_revision=since_revision,
                max_sensitivity=max_sensitivity,
                max_claims=max_claims,
                max_bytes=max_bytes,
                ttl_seconds=ttl_seconds,
            )
        except exchange.ContextExchangeError as error:
            raise ConnectorError(str(error)) from error
        envelope = seal_mailbox_payload(
            pull_request,
            kind="coordination-note",
            project_id=str(config["project_id"]),
            sender=str(config["principal"]),
            recipient=recipient,
            recipient_mailbox_key=mailbox_public,
            ttl_seconds=ttl_seconds,
            inner_expires_at=int(pull_request["expires_at"]),
        )
        request_id = str(pull_request["request_id"])
        state_path = self.exchange_state_path(alias, "outbound", request_id)
        bridge.save_protected_json(
            state_path,
            {
                "format": "context-pull-state/v1",
                "direction": "outbound",
                "state": "queued",
                "message_id": envelope["message_id"],
                "request": pull_request,
                "response": None,
                "updated_at": int(time.time()),
            },
        )
        outbox = self._queue_envelope(
            alias,
            envelope,
            request_id=request_id,
            exchange_direction="outbound",
        )
        return {
            "queued": True,
            "request_id": request_id,
            "message_id": envelope["message_id"],
            "recipient": recipient,
            "purpose": pull_request["purpose"],
            "question": pull_request["question"],
            "selectors": pull_request["selectors"],
            "since_revision": pull_request["since_revision"],
            "expires_at": pull_request["expires_at"],
            "outbox": str(outbox),
        }

    def requests(self, alias: str) -> dict[str, Any]:
        """Return a bounded, assertion-free view of local pull-request state."""
        records: list[dict[str, Any]] = []
        base = self.home / "team-exchanges" / _safe_alias(alias)
        for direction in ("inbound", "outbound"):
            folder = base / direction
            paths = sorted(
                folder.glob("*.json"),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )[:100]
            for path in paths:
                state = bridge.load_protected_json(path)
                pull_request = state.get("request")
                if not isinstance(pull_request, Mapping):
                    raise ConnectorError(
                        f"Invalid Context Pull Request state: {path.name}"
                    )
                try:
                    verified = exchange.verify_request(pull_request, allow_expired=True)
                except exchange.ContextExchangeError as error:
                    raise ConnectorError(
                        f"Invalid Context Pull Request state: {path.name}"
                    ) from error
                response = state.get("response")
                response_view = None
                if isinstance(response, Mapping):
                    response_view = {
                        key: response.get(key)
                        for key in (
                            "response_id",
                            "request_sha256",
                            "status",
                            "note",
                            "created_at",
                            "expires_at",
                        )
                    }
                records.append(
                    {
                        "direction": direction,
                        "state": state.get("state"),
                        "request_id": verified["request_id"],
                        "peer": (
                            verified["sender"]
                            if direction == "inbound"
                            else verified["recipient"]
                        ),
                        "purpose": verified["purpose"],
                        "question": verified["question"],
                        "selectors": verified["selectors"],
                        "since_revision": verified["since_revision"],
                        "max_sensitivity": verified["max_sensitivity"],
                        "max_claims": verified["max_claims"],
                        "max_bytes": verified["max_bytes"],
                        "created_at": verified["created_at"],
                        "expires_at": verified["expires_at"],
                        "response": response_view,
                    }
                )
        return {
            "project": alias,
            "requests": sorted(
                records,
                key=lambda item: (int(item["created_at"]), item["request_id"]),
                reverse=True,
            ),
        }

    def publish_head(
        self,
        alias: str,
        ledger_project: str,
        audience: str,
        purpose: str,
        max_sensitivity: str,
    ) -> dict[str, Any]:
        if audience not in {"team", "project-agents"}:
            raise ConnectorError("Invalid publication audience.")
        if max_sensitivity not in {"public", "internal", "confidential", "restricted"}:
            raise ConnectorError("Invalid publication sensitivity.")
        if not purpose.strip() or len(purpose) > 500:
            raise ConnectorError("Publication purpose must be 1 to 500 characters.")
        with _file_lock(self.lock_path(alias)):
            config = self.load_config(alias)
            ledger = ContextLedger(ledger_project, self.home)
            heads = ledger.status()["heads"]
            if not heads:
                return {
                    "revision": None,
                    "queued": [],
                    "skipped": [],
                    "reason": "no-head",
                }
            if len(heads) != 1:
                raise ConnectorError(
                    "Ledger has divergent heads; reconcile them before automated publication."
                )
            revision = str(heads[0])
            directory = self.directory(alias)
            endpoints = directory.get("endpoints")
            if not isinstance(endpoints, list):
                raise ConnectorError("Team Hub directory is invalid.")
            targets = [
                endpoint
                for endpoint in endpoints
                if isinstance(endpoint, dict)
                and endpoint.get("principal") != config["principal"]
                and (audience == "team" or endpoint.get("role") == "project-agent")
            ]
            untrusted = [
                str(endpoint["principal"])
                for endpoint in targets
                if endpoint.get("trust") != "trusted"
            ]
            if untrusted:
                raise ConnectorError(
                    "Publication target is not locally trusted: " + ", ".join(untrusted)
                )
            published = dict(config["published"])
            queued: list[dict[str, Any]] = []
            skipped: list[str] = []
            temporary_root = self.home / "team-publish" / _safe_alias(alias)
            for endpoint in targets:
                recipient = str(endpoint.get("principal", ""))
                try:
                    hub._principal(recipient, "publication recipient")
                except hub.HubError as error:
                    raise ConnectorError(str(error)) from error
                if published.get(recipient) == revision:
                    skipped.append(recipient)
                    continue
                temporary = temporary_root / f"{secrets.token_hex(16)}.json"
                try:
                    ledger.export(
                        revision,
                        temporary,
                        recipient=recipient,
                        purpose=purpose.strip(),
                        max_sensitivity=max_sensitivity,
                    )
                    queued.append(
                        self.queue_bundle(
                            alias,
                            temporary,
                            hub.DEFAULT_MESSAGE_TTL_SECONDS,
                        )
                    )
                finally:
                    temporary.unlink(missing_ok=True)
                published[recipient] = revision
                config["published"] = published
                self.save_config(alias, config)
            return {"revision": revision, "queued": queued, "skipped": skipped}

    @staticmethod
    def _requested_claim_ids(
        ledger: ContextLedger, pull_request: Mapping[str, Any]
    ) -> tuple[str, list[str], bool]:
        heads = ledger.status()["heads"]
        if not heads:
            return "", [], False
        if len(heads) != 1:
            raise ConnectorError(
                "Ledger has divergent heads; reconcile them before answering a pull request."
            )
        head = str(heads[0])
        active = {
            str(claim["id"]): claim for claim in ledger.freshness()["active_claims"]
        }
        candidates = set(active)
        removed: list[Mapping[str, Any]] = []
        since_revision = pull_request.get("since_revision")
        if since_revision is not None:
            try:
                delta = ledger.diff(str(since_revision), head)
            except ValueError as error:
                raise ConnectorError(
                    "The requested since-revision is not available in this ledger; "
                    "respond with needs-clarification instead of sending a full snapshot."
                ) from error
            candidates = {str(claim["id"]) for claim in delta["added"]} | {
                str(change["after"]["id"]) for change in delta["changed"]
            }
            removed = delta["removed"]
        selectors = pull_request["selectors"]
        kinds = set(selectors["kinds"])
        semantic_keys = set(selectors["semantic_keys"])
        labels = set(selectors["labels"])
        sensitivity_order = {
            "public": 0,
            "internal": 1,
            "confidential": 2,
            "restricted": 3,
        }
        ceiling = sensitivity_order[str(pull_request["max_sensitivity"])]

        def matches(claim: Mapping[str, Any]) -> bool:
            return (
                (not kinds or claim.get("kind") in kinds)
                and (not semantic_keys or claim.get("semantic_key") in semantic_keys)
                and (not labels or labels.intersection(claim.get("labels", [])))
                and sensitivity_order[claim.get("sensitivity", "internal")] <= ceiling
            )

        has_lifecycle_removal = any(matches(claim) for claim in removed)
        selected = [
            active[claim_id]
            for claim_id in candidates
            if claim_id in active and matches(active[claim_id])
        ]
        priority = {
            "blocker": 0,
            "decision": 1,
            "constraint": 2,
            "action": 3,
            "disagreement": 4,
            "fact": 5,
            "question": 6,
            "hypothesis": 7,
        }
        selected.sort(key=lambda claim: str(claim["id"]))
        selected.sort(key=lambda claim: str(claim.get("observed_at", "")), reverse=True)
        selected.sort(key=lambda claim: priority.get(str(claim["kind"]), 99))
        chosen: list[str] = []
        # The signed ceiling is measured over the canonical claims array, not
        # the sum of independently encoded objects. Account for ``[]`` and the
        # comma separators exactly as requester-side verification does.
        used = 2
        for claim in selected:
            encoded = len(canonical_context_json(claim)) + (1 if chosen else 0)
            if len(chosen) >= int(pull_request["max_claims"]):
                break
            if used + encoded > int(pull_request["max_bytes"]):
                continue
            chosen.append(str(claim["id"]))
            used += encoded
        return head, chosen, has_lifecycle_removal

    def respond(
        self,
        alias: str,
        ledger_project: str,
        request_id: str,
        *,
        status: str = "fulfilled",
        note: str = "",
    ) -> dict[str, Any]:
        """Answer one authenticated pull request with a minimized Context Pack."""
        if status not in exchange.RESPONSE_STATUSES:
            raise ConnectorError("Context Pull Response status is invalid.")
        with _file_lock(self.lock_path(alias)):
            config = self.load_config(alias)
            state_path = self.exchange_state_path(alias, "inbound", request_id)
            if not state_path.exists():
                raise ConnectorError("Inbound Context Pull Request was not found.")
            state = bridge.load_protected_json(state_path)
            if state.get("state") != "open":
                raise ConnectorError(
                    "Context Pull Request already has a final response."
                )
            pull_request = state.get("request")
            if not isinstance(pull_request, Mapping):
                raise ConnectorError("Inbound Context Pull Request state is invalid.")
            try:
                verified_request = exchange.verify_request(
                    pull_request,
                    expected_project=str(config["project_id"]),
                    expected_recipient=str(config["principal"]),
                )
            except exchange.ContextExchangeError as error:
                raise ConnectorError(str(error)) from error
            peer = self._trusted_endpoint(alias, str(verified_request["sender"]))
            bundle: Mapping[str, Any] | None = None
            selected_claims: list[str] = []
            head = ""
            effective_status = status
            effective_note = note
            if status == "fulfilled":
                ledger = ContextLedger(ledger_project, self.home)
                head, selected_claims, has_lifecycle_removal = (
                    self._requested_claim_ids(ledger, verified_request)
                )
                if has_lifecycle_removal:
                    effective_status = "needs-clarification"
                    effective_note = note or (
                        "Matching lifecycle removals cannot be represented by Context "
                        "Pull Request v1; send a reviewed checkpoint instead."
                    )
                    selected_claims = []
                elif not selected_claims:
                    effective_status = "no-change"
                    effective_note = note or "No matching active context change."
                else:
                    disclosure = ledger.disclose(
                        str(verified_request["sender"]),
                        head,
                        claim_ids=selected_claims,
                        purpose=str(verified_request["purpose"]),
                        max_sensitivity=str(verified_request["max_sensitivity"]),
                    )
                    bundle = disclosure["bundle"]
            identity = load_or_create_identity(self.identity_path)
            try:
                response = exchange.create_response(
                    identity,
                    verified_request,
                    status=effective_status,
                    bundle=bundle,
                    note=effective_note,
                )
            except exchange.ContextExchangeError as error:
                raise ConnectorError(str(error)) from error
            mailbox_public = _b64d(peer.get("mailbox_public_key"), 64)
            envelope = seal_mailbox_payload(
                response,
                kind="coordination-note",
                project_id=str(config["project_id"]),
                sender=str(config["principal"]),
                recipient=str(verified_request["sender"]),
                recipient_mailbox_key=mailbox_public,
                ttl_seconds=max(1, int(response["expires_at"]) - int(time.time())),
                inner_expires_at=int(response["expires_at"]),
            )
            outbox = self._queue_envelope(
                alias,
                envelope,
                request_id=str(verified_request["request_id"]),
                exchange_direction="inbound",
            )
            state["state"] = "response-queued"
            state["response"] = response
            state["response_message_id"] = envelope["message_id"]
            state["updated_at"] = int(time.time())
            bridge.save_protected_json(state_path, state)
        return {
            "request_id": verified_request["request_id"],
            "response_id": response["response_id"],
            "status": response["status"],
            "recipient": response["recipient"],
            "source_revision": head or None,
            "claim_ids": selected_claims,
            "message_id": envelope["message_id"],
            "outbox": str(outbox),
        }

    def _mark_exchange_sent(self, alias: str, record: Mapping[str, Any]) -> None:
        request_id = record.get("request_id")
        direction = record.get("exchange_direction")
        if not isinstance(request_id, str) or direction not in {"inbound", "outbound"}:
            return
        state_path = self.exchange_state_path(alias, str(direction), request_id)
        if not state_path.exists():
            raise ConnectorError("Context Pull Request state disappeared before send.")
        state = bridge.load_protected_json(state_path)
        state["state"] = "responded" if direction == "inbound" else "sent"
        state["updated_at"] = int(time.time())
        bridge.save_protected_json(state_path, state)

    def _dead_letter(
        self, alias: str, path: Path, record: dict[str, Any], reason: str
    ) -> None:
        """Retire a permanently-undeliverable outbox entry so it cannot wedge the drain."""
        dead = self.home / "team-deadletter" / _safe_alias(alias)
        retired_at = int(time.time())
        dead.mkdir(parents=True, exist_ok=True)
        # Persist the complete protected record before removing the retry copy.
        # If this write fails, the exception propagates and the outbox survives.
        bridge.save_protected_json(
            dead / path.name,
            {
                "outbox_record": record,
                "reason": reason,
                "retired_at": retired_at,
            },
        )
        request_id = record.get("request_id")
        direction = record.get("exchange_direction")
        if isinstance(request_id, str) and direction in {"inbound", "outbound"}:
            state_path = self.exchange_state_path(alias, str(direction), request_id)
            if state_path.exists():
                state = bridge.load_protected_json(state_path)
                state["state"] = "delivery-failed"
                state["delivery_failure"] = {
                    "reason": reason[:500],
                    "retired_at": retired_at,
                }
                state["updated_at"] = retired_at
                bridge.save_protected_json(state_path, state)
        path.unlink(missing_ok=True)

    def flush(self, alias: str) -> list[dict[str, Any]]:
        config = self.load_config(alias)
        outbox = self.home / "team-outbox" / _safe_alias(alias)
        results: list[dict[str, Any]] = []
        for path in sorted(outbox.glob("*.json")) if outbox.exists() else []:
            record = bridge.load_protected_json(path)
            envelope = record.get("envelope")
            if not isinstance(envelope, dict):
                self._dead_letter(alias, path, record, "Outbox entry is malformed.")
                continue
            try:
                result = self.client(config).authenticated(
                    "/v1/mailbox/push",
                    {"envelope": envelope},
                    self.identity_path,
                )
            except PermanentRejectionError as failure:
                # A definitive, permanent rejection (expired envelope, recipient
                # left the project, message-id conflict): retire the entry so one
                # stuck message cannot permanently block all future send AND
                # receive.
                self._dead_letter(alias, path, record, str(failure))
                continue
            # Transient failures AND ambiguous outcomes (unverifiable/mismatched
            # response, redirect, network) propagate so the next sync retries in
            # order; push is idempotent (the hub dedups by message-id), so a
            # maybe-delivered message is never silently discarded.
            if result.get("message_id") != envelope.get("message_id"):
                raise ConnectorError("Team Hub acknowledged another message.")
            self._mark_exchange_sent(alias, record)
            path.unlink(missing_ok=True)
            results.append(result)
        return results

    def _existing_quarantine_token(
        self, ledger: ContextLedger, source_name: str
    ) -> str | None:
        if not ledger.quarantine.exists():
            return None
        for path in ledger.quarantine.glob("*.json"):
            try:
                record = _read_json(path)
            except ConnectorError:
                continue
            if record.get("source_name") == source_name:
                return path.stem
        return None

    def _quarantine_bundle(
        self,
        alias: str,
        ledger_project: str,
        message_id: str,
        bundle: Mapping[str, Any],
    ) -> str:
        ledger = ContextLedger(ledger_project, self.home)
        source_name = f"hub-{message_id}.json"
        existing = self._existing_quarantine_token(ledger, source_name)
        if existing:
            return existing
        incoming = self.home / "team-incoming" / _safe_alias(alias)
        source = incoming / source_name
        bridge.save_json(source, dict(bundle))
        try:
            return ledger.import_quarantine(source)
        finally:
            source.unlink(missing_ok=True)

    def _record_rejection(
        self, alias: str, sequence: int, envelope: Mapping[str, Any], reason: str
    ) -> None:
        rejection = self.home / "team-rejections" / _safe_alias(alias)
        message_id = str(envelope.get("message_id", f"sequence-{sequence}"))
        digest = hashlib.sha256(canonical_bytes(dict(envelope))).hexdigest()
        bridge.save_json(
            rejection / f"{message_id}.json",
            {
                "format": CONNECTOR_FORMAT,
                "message_id": message_id,
                "sequence": sequence,
                "envelope_digest": digest,
                "rejected_at": int(time.time()),
                "reason": reason[:500],
            },
        )

    def _store_inbound_request(
        self,
        alias: str,
        config: Mapping[str, Any],
        payload: Mapping[str, Any],
        message_id: str,
    ) -> dict[str, Any]:
        try:
            pull_request = exchange.verify_request(
                payload,
                expected_project=str(config["project_id"]),
                expected_recipient=str(config["principal"]),
            )
        except exchange.ContextExchangeError as error:
            raise ConnectorError(str(error)) from error
        request_id = str(pull_request["request_id"])
        state_path = self.exchange_state_path(alias, "inbound", request_id)
        if state_path.exists():
            existing = bridge.load_protected_json(state_path)
            recorded = existing.get("request")
            if not isinstance(recorded, Mapping) or exchange.exchange_digest(
                recorded
            ) != exchange.exchange_digest(pull_request):
                raise ConnectorError(
                    "Context Pull Request ID is bound to different content."
                )
            duplicate = True
        else:
            bridge.save_protected_json(
                state_path,
                {
                    "format": "context-pull-state/v1",
                    "direction": "inbound",
                    "state": "open",
                    "message_id": message_id,
                    "request": pull_request,
                    "response": None,
                    "updated_at": int(time.time()),
                },
            )
            duplicate = False
        return {
            "message_id": message_id,
            "request_id": request_id,
            "sender": pull_request["sender"],
            "purpose": pull_request["purpose"],
            "question": pull_request["question"],
            "selectors": pull_request["selectors"],
            "since_revision": pull_request["since_revision"],
            "expires_at": pull_request["expires_at"],
            "duplicate": duplicate,
        }

    @staticmethod
    def _validate_response_claims(
        response: Mapping[str, Any], pull_request: Mapping[str, Any]
    ) -> dict[str, Any]:
        bundle = response.get("bundle")
        if not isinstance(bundle, dict):
            raise ConnectorError(
                "Fulfilled Context Pull Response lacks a Context Pack."
            )
        try:
            metadata = bridge.validate_disclosure_bundle(
                bundle, str(pull_request["sender"])
            )
        except ValueError as error:
            raise ConnectorError(str(error)) from error
        # The endpoint identity signs its selection of this exact bundle digest;
        # the Context Ledger author separately signs the Context Pack itself.
        # They are deliberately distinct keys so connector compromise cannot
        # impersonate ledger authorship.
        revision = bundle["export"]["revision"]
        if revision.get("scope", {}).get("purpose") != pull_request.get("purpose"):
            raise ConnectorError(
                "Context Pull Response purpose does not match the request."
            )
        claims = revision.get("claims")
        if not isinstance(claims, list) or not claims:
            raise ConnectorError("Fulfilled Context Pull Response has no claims.")
        if len(claims) > int(pull_request["max_claims"]):
            raise ConnectorError(
                "Context Pull Response exceeds the requested claim limit."
            )
        if len(canonical_context_json(claims)) > int(pull_request["max_bytes"]):
            raise ConnectorError(
                "Context Pull Response exceeds the requested byte limit."
            )
        selectors = pull_request["selectors"]
        kinds = set(selectors["kinds"])
        semantic_keys = set(selectors["semantic_keys"])
        labels = set(selectors["labels"])
        sensitivity_order = {
            "public": 0,
            "internal": 1,
            "confidential": 2,
            "restricted": 3,
        }
        ceiling = sensitivity_order[str(pull_request["max_sensitivity"])]
        for claim in claims:
            if kinds and claim.get("kind") not in kinds:
                raise ConnectorError(
                    "Context Pull Response violates its kind selector."
                )
            if semantic_keys and claim.get("semantic_key") not in semantic_keys:
                raise ConnectorError(
                    "Context Pull Response violates its semantic-key selector."
                )
            if labels and not labels.intersection(claim.get("labels", [])):
                raise ConnectorError(
                    "Context Pull Response violates its label selector."
                )
            if sensitivity_order[claim.get("sensitivity", "internal")] > ceiling:
                raise ConnectorError(
                    "Context Pull Response exceeds the requested sensitivity."
                )
        return metadata

    def _store_inbound_response(
        self,
        alias: str,
        ledger_project: str,
        config: Mapping[str, Any],
        payload: Mapping[str, Any],
        message_id: str,
    ) -> dict[str, Any]:
        request_id = payload.get("request_id")
        if not isinstance(request_id, str):
            raise ConnectorError("Context Pull Response request ID is invalid.")
        state_path = self.exchange_state_path(alias, "outbound", request_id)
        if not state_path.exists():
            raise ConnectorError("Unsolicited Context Pull Response was rejected.")
        state = bridge.load_protected_json(state_path)
        pull_request = state.get("request")
        if not isinstance(pull_request, Mapping):
            raise ConnectorError("Outbound Context Pull Request state is invalid.")
        try:
            response = exchange.verify_response(
                payload,
                request=pull_request,
                expected_project=str(config["project_id"]),
                expected_recipient=str(config["principal"]),
            )
        except exchange.ContextExchangeError as error:
            raise ConnectorError(str(error)) from error
        existing = state.get("response")
        if isinstance(existing, Mapping):
            if exchange.exchange_digest(existing) != exchange.exchange_digest(response):
                raise ConnectorError(
                    "Context Pull Request already has a different final response."
                )
            return {
                "message_id": message_id,
                "request_id": request_id,
                "response_id": response["response_id"],
                "status": response["status"],
                "quarantine_token": state.get("quarantine_token"),
                "duplicate": True,
            }
        token = None
        if response["status"] == "fulfilled":
            self._validate_response_claims(response, pull_request)
            token = self._quarantine_bundle(
                alias, ledger_project, message_id, response["bundle"]
            )
        state["state"] = "response-received"
        state["response"] = response
        state["response_message_id"] = message_id
        state["quarantine_token"] = token
        state["updated_at"] = int(time.time())
        bridge.save_protected_json(state_path, state)
        return {
            "message_id": message_id,
            "request_id": request_id,
            "response_id": response["response_id"],
            "status": response["status"],
            "note": response["note"],
            "quarantine_token": token,
            "duplicate": False,
        }

    def pull(self, alias: str, ledger_project: str) -> dict[str, Any]:
        config = self.load_config(alias)
        client = self.client(config)
        directory = self.directory(alias)
        trusted_senders = {
            str(endpoint["principal"])
            for endpoint in directory["endpoints"]
            if endpoint.get("trust") == "trusted"
        }
        cursor = int(config["cursor"])
        quarantined: list[dict[str, Any]] = []
        pull_requests: list[dict[str, Any]] = []
        pull_responses: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        truncated = False
        for _ in range(MAX_SYNC_PAGES):
            page = client.authenticated(
                "/v1/mailbox/pull",
                {"project_id": config["project_id"], "after": cursor, "limit": 32},
                self.identity_path,
            )
            messages = page.get("messages")
            if not isinstance(messages, list):
                raise ConnectorError("Team Hub mailbox page is invalid.")
            if not messages:
                break
            for item in messages:
                if not isinstance(item, dict) or set(item) != {"sequence", "envelope"}:
                    raise ConnectorError("Team Hub mailbox item is invalid.")
                sequence, envelope = item["sequence"], item["envelope"]
                if isinstance(sequence, bool) or not isinstance(sequence, int):
                    raise ConnectorError("Team Hub mailbox sequence is invalid.")
                if sequence <= cursor or not isinstance(envelope, dict):
                    raise ConnectorError("Team Hub mailbox ordering is invalid.")
                try:
                    message_id = hub._identifier(
                        envelope.get("message_id"), "mailbox message ID"
                    )
                except hub.HubError as error:
                    raise ConnectorError(str(error)) from error
                try:
                    if envelope.get("sender") not in trusted_senders:
                        raise ConnectorError(
                            "Mailbox envelope sender is not locally trusted."
                        )
                    kind = envelope.get("kind")
                    if kind == "context-pack":
                        bundle = open_context_pack(
                            envelope,
                            mailbox_identity=self.mailbox_identity,
                            expected_project=str(config["project_id"]),
                            expected_recipient=str(config["principal"]),
                        )
                        token = self._quarantine_bundle(
                            alias, ledger_project, message_id, bundle
                        )
                        quarantined.append(
                            {
                                "message_id": message_id,
                                "sequence": sequence,
                                "quarantine_token": token,
                            }
                        )
                    elif kind == "coordination-note":
                        payload = open_mailbox_payload(
                            envelope,
                            mailbox_identity=self.mailbox_identity,
                            expected_project=str(config["project_id"]),
                            expected_recipient=str(config["principal"]),
                            expected_kind="coordination-note",
                        )
                        if payload.get("format") == exchange.REQUEST_FORMAT:
                            if payload.get("sender") != envelope.get("sender"):
                                raise ConnectorError(
                                    "Context Pull Request sender does not match envelope."
                                )
                            received_request = self._store_inbound_request(
                                alias, config, payload, message_id
                            )
                            received_request["sequence"] = sequence
                            pull_requests.append(received_request)
                        elif payload.get("format") == exchange.RESPONSE_FORMAT:
                            if payload.get("sender") != envelope.get("sender"):
                                raise ConnectorError(
                                    "Context Pull Response sender does not match envelope."
                                )
                            received_response = self._store_inbound_response(
                                alias, ledger_project, config, payload, message_id
                            )
                            received_response["sequence"] = sequence
                            pull_responses.append(received_response)
                            if received_response.get("quarantine_token"):
                                quarantined.append(
                                    {
                                        "message_id": message_id,
                                        "sequence": sequence,
                                        "quarantine_token": received_response[
                                            "quarantine_token"
                                        ],
                                        "request_id": received_response["request_id"],
                                    }
                                )
                        else:
                            raise ConnectorError(
                                "Unsupported encrypted coordination payload."
                            )
                    else:
                        raise ConnectorError("Unsupported mailbox envelope kind.")
                except (ConnectorError, ValueError) as failure:
                    self._record_rejection(alias, sequence, envelope, str(failure))
                    rejected.append(
                        {
                            "message_id": message_id,
                            "sequence": sequence,
                            "reason": str(failure),
                        }
                    )
                client.authenticated(
                    "/v1/mailbox/ack",
                    {
                        "project_id": config["project_id"],
                        "message_ids": [message_id],
                    },
                    self.identity_path,
                )
                cursor = sequence
                config["cursor"] = cursor
                self.save_config(alias, config)
            if not page.get("has_more"):
                break
        else:
            # Hit the per-sync page cap. The cursor is persisted after every
            # message, so treat a large backlog as backpressure (resume on the
            # next sync) rather than a fatal error that would crash the run loop.
            truncated = True
        return {
            "project": alias,
            "cursor": cursor,
            "quarantined": quarantined,
            "requests": pull_requests,
            "responses": pull_responses,
            "rejected": rejected,
            "truncated": truncated,
        }

    def sync(self, alias: str, ledger_project: str) -> dict[str, Any]:
        with _file_lock(self.lock_path(alias)):
            sent = self.flush(alias)
            received = self.pull(alias, ledger_project)
        return {"sent": sent, **received}


def _read_code(args: argparse.Namespace) -> str:
    if args.code_file:
        path = Path(args.code_file).expanduser()
        if path.stat().st_size > 8192:
            raise ConnectorError("Enrollment code file is too large.")
        return path.read_text(encoding="utf-8").strip()
    if not sys.stdin.isatty():
        return sys.stdin.readline().strip()
    raise ConnectorError("Provide the enrollment code with --code-file or stdin.")


def _read_question(args: argparse.Namespace) -> str:
    if args.question_file:
        path = Path(args.question_file).expanduser()
        if path.stat().st_size > exchange.MAX_QUESTION_CHARS * 4:
            raise ConnectorError("Context Pull Request question file is too large.")
        return path.read_text(encoding="utf-8").strip()
    if not sys.stdin.isatty():
        return sys.stdin.read(exchange.MAX_QUESTION_CHARS + 1).strip()
    raise ConnectorError("Provide the question with --question-file or stdin.")


def _read_optional_question(args: argparse.Namespace) -> str | None:
    """Read an incident question from a file, or fall back to the preset text.

    Deliberately does not consume stdin: an incident command must never block
    an on-call operator waiting for input that will not arrive.
    """
    if not args.question_file:
        return None
    path = Path(args.question_file).expanduser()
    if path.stat().st_size > exchange.MAX_QUESTION_CHARS * 4:
        raise ConnectorError("Context Pull Request question file is too large.")
    return path.read_text(encoding="utf-8").strip()


def _print(value: Mapping[str, Any]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def command_enroll(args: argparse.Namespace) -> None:
    _print(TeamConnector(args.home).enroll(args.project, _read_code(args)))


def command_directory(args: argparse.Namespace) -> None:
    _print(TeamConnector(args.home).directory(args.project))


def command_status(args: argparse.Namespace) -> None:
    _print(TeamConnector(args.home).status(args.project))


def command_trust(args: argparse.Namespace) -> None:
    _print(TeamConnector(args.home).trust(args.project, args.principal))


def command_untrust(args: argparse.Namespace) -> None:
    _print(TeamConnector(args.home).untrust(args.project, args.principal))


def command_request(args: argparse.Namespace) -> None:
    _print(
        TeamConnector(args.home).queue_request(
            args.project,
            recipient=args.to,
            purpose=args.purpose,
            question=_read_question(args),
            kinds=args.kind,
            semantic_keys=args.semantic_key,
            labels=args.label,
            since_revision=args.since_revision,
            max_sensitivity=args.max_sensitivity,
            max_claims=args.max_claims,
            max_bytes=args.max_bytes,
            ttl_seconds=args.ttl_seconds,
        )
    )


def command_requests(args: argparse.Namespace) -> None:
    _print(TeamConnector(args.home).requests(args.project))


def command_respond(args: argparse.Namespace) -> None:
    _print(
        TeamConnector(args.home).respond(
            args.project,
            args.ledger_project,
            args.request_id,
            status=args.status,
            note=args.note,
        )
    )


def command_incident_ask(args: argparse.Namespace) -> None:
    _print(
        incident.ask(
            TeamConnector(args.home),
            args.project,
            recipient=args.to,
            purpose=args.purpose,
            question=_read_optional_question(args),
            severity=args.severity,
            since_revision=args.since_revision,
        )
    )


def command_incident_brief(args: argparse.Namespace) -> None:
    endpoint = TeamConnector(args.home)
    brief = incident.build_brief(
        ContextLedger(args.ledger_project, endpoint.home),
        project=args.project,
        ledger_project=args.ledger_project,
        since_revision=args.since_revision,
    )
    if args.json:
        _print(brief)
    else:
        print(incident.render_brief(brief))


def command_incident_status(args: argparse.Namespace) -> None:
    _print(
        incident.build_status(
            TeamConnector(args.home), args.project, args.ledger_project
        )
    )


def command_queue(args: argparse.Namespace) -> None:
    _print(
        TeamConnector(args.home).queue_bundle(
            args.project, Path(args.bundle_file).expanduser(), args.ttl_seconds
        )
    )


def command_publish(args: argparse.Namespace) -> None:
    _print(
        TeamConnector(args.home).publish_head(
            args.project,
            args.ledger_project,
            args.audience,
            args.purpose,
            args.max_sensitivity,
        )
    )


def command_sync(args: argparse.Namespace) -> None:
    _print(TeamConnector(args.home).sync(args.project, args.ledger_project))


def command_run(args: argparse.Namespace) -> None:
    if args.interval_seconds < 10:
        raise ConnectorError("Sync interval must be at least 10 seconds.")
    if (
        args.retry_min_seconds < 1
        or args.retry_max_seconds < args.retry_min_seconds
        or args.retry_max_seconds > args.interval_seconds
    ):
        raise ConnectorError(
            "Retry bounds must be positive, ordered, and no longer than the sync interval."
        )
    stopped = threading.Event()

    def stop(_signum: int, _frame: Any) -> None:
        stopped.set()

    for name in ("SIGINT", "SIGTERM"):
        available = getattr(signal, name, None)
        if available is not None:
            signal.signal(available, stop)
    iteration = 0
    consecutive_failures = 0
    while not stopped.is_set():
        iteration += 1
        try:
            active = TeamConnector(args.home)
            publication = None
            if args.publish_head:
                publication = active.publish_head(
                    args.project,
                    args.ledger_project,
                    args.audience,
                    args.purpose,
                    args.max_sensitivity,
                )
            result = active.sync(args.project, args.ledger_project)
            consecutive_failures = 0
            _print(
                {
                    "iteration": iteration,
                    "status": "ok",
                    "synced_at": int(time.time()),
                    "publication": publication,
                    **result,
                }
            )
            wait_seconds = args.interval_seconds
        except TransientConnectorError as failure:
            consecutive_failures += 1
            wait_seconds = min(
                args.retry_max_seconds,
                args.retry_min_seconds * (2 ** min(consecutive_failures - 1, 16)),
            )
            print(
                json.dumps(
                    {
                        "iteration": iteration,
                        "status": "retrying",
                        "failed_at": int(time.time()),
                        "consecutive_failures": consecutive_failures,
                        "retry_in_seconds": wait_seconds,
                        "error": str(failure),
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )
        if args.iterations and iteration >= args.iterations:
            break
        stopped.wait(wait_seconds)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, help="Endpoint Braid state root.")
    parser.add_argument("--version", action="version", version="%(prog)s 0.5.0")
    commands = parser.add_subparsers(dest="command", required=True)

    enroll = commands.add_parser(
        "enroll", help="Enroll this endpoint into a team project."
    )
    enroll.add_argument("--project", required=True, help="Local logical project alias.")
    enroll.add_argument("--code-file")
    enroll.set_defaults(handler=command_enroll)

    directory = commands.add_parser(
        "directory", help="List enrolled project endpoints."
    )
    directory.add_argument("--project", required=True)
    directory.set_defaults(handler=command_directory)

    status = commands.add_parser(
        "status", help="Show endpoint and remote mailbox state."
    )
    status.add_argument("--project", required=True)
    status.set_defaults(handler=command_status)

    trust = commands.add_parser(
        "trust",
        help="Approve one endpoint principal and its signed mailbox binding.",
    )
    trust.add_argument("--project", required=True)
    trust.add_argument("--principal", required=True)
    trust.set_defaults(handler=command_trust)

    untrust = commands.add_parser(
        "untrust", help="Remove local approval for one endpoint principal."
    )
    untrust.add_argument("--project", required=True)
    untrust.add_argument("--principal", required=True)
    untrust.set_defaults(handler=command_untrust)

    pull_request = commands.add_parser(
        "request",
        help="Queue a signed request for a bounded semantic context change.",
    )
    pull_request.add_argument("--project", required=True)
    pull_request.add_argument("--to", required=True, help="Trusted endpoint principal.")
    pull_request.add_argument("--purpose", required=True)
    pull_request.add_argument("--question-file")
    pull_request.add_argument(
        "--kind", action="append", choices=sorted(exchange.CLAIM_KINDS), default=[]
    )
    pull_request.add_argument("--semantic-key", action="append", default=[])
    pull_request.add_argument("--label", action="append", default=[])
    pull_request.add_argument("--since-revision")
    pull_request.add_argument(
        "--max-sensitivity",
        choices=("public", "internal", "confidential", "restricted"),
        default="internal",
    )
    pull_request.add_argument("--max-claims", type=int, default=50)
    pull_request.add_argument("--max-bytes", type=int, default=250_000)
    pull_request.add_argument(
        "--ttl-seconds", type=int, default=hub.DEFAULT_MESSAGE_TTL_SECONDS
    )
    pull_request.set_defaults(handler=command_request)

    requests = commands.add_parser(
        "requests", help="List inbound and outbound Context Pull Requests."
    )
    requests.add_argument("--project", required=True)
    requests.set_defaults(handler=command_requests)

    respond = commands.add_parser(
        "respond", help="Answer one Context Pull Request without expanding its scope."
    )
    respond.add_argument("--project", required=True)
    respond.add_argument("--ledger-project", required=True)
    respond.add_argument("--request-id", required=True)
    respond.add_argument(
        "--status",
        choices=sorted(exchange.RESPONSE_STATUSES),
        default="fulfilled",
    )
    respond.add_argument("--note", default="")
    respond.set_defaults(handler=command_respond)

    incident_parser = commands.add_parser(
        "incident",
        help="On-call incident handoff: ask, brief, and open-state triage.",
    )
    incident_commands = incident_parser.add_subparsers(
        dest="incident_command", required=True
    )

    incident_ask = incident_commands.add_parser(
        "ask",
        help="Queue the curated incident Context Pull Request preset.",
    )
    incident_ask.add_argument("--project", required=True)
    incident_ask.add_argument("--to", required=True, help="Trusted endpoint principal.")
    incident_ask.add_argument("--purpose", required=True)
    incident_ask.add_argument(
        "--severity",
        choices=incident.SEVERITIES,
        default=incident.DEFAULT_SEVERITY,
    )
    incident_ask.add_argument("--since-revision")
    incident_ask.add_argument("--question-file")
    incident_ask.set_defaults(handler=command_incident_ask)

    incident_brief = incident_commands.add_parser(
        "brief",
        help="Render a read-only on-call brief from the local reviewed ledger.",
    )
    incident_brief.add_argument("--project", required=True)
    incident_brief.add_argument("--ledger-project", required=True)
    incident_brief.add_argument("--since-revision")
    incident_brief.add_argument("--json", action="store_true")
    incident_brief.set_defaults(handler=command_incident_brief)

    incident_status = incident_commands.add_parser(
        "status",
        help="Show pending requests, quarantined responses, and open conflicts.",
    )
    incident_status.add_argument("--project", required=True)
    incident_status.add_argument("--ledger-project", required=True)
    incident_status.set_defaults(handler=command_incident_status)

    queue = commands.add_parser(
        "queue",
        help="Encrypt an approved recipient-bound Context Pack into the outbox.",
    )
    queue.add_argument("--project", required=True)
    queue.add_argument("--bundle-file", required=True)
    queue.add_argument(
        "--ttl-seconds", type=int, default=hub.DEFAULT_MESSAGE_TTL_SECONDS
    )
    queue.set_defaults(handler=command_queue)

    publish = commands.add_parser(
        "publish",
        help="Queue the current reviewed ledger head for a team or project agents.",
    )
    publish.add_argument("--project", required=True)
    publish.add_argument("--ledger-project", required=True)
    publish.add_argument(
        "--audience", choices=("team", "project-agents"), default="project-agents"
    )
    publish.add_argument("--purpose", default="Scheduled project checkpoint")
    publish.add_argument(
        "--max-sensitivity",
        choices=("public", "internal", "confidential", "restricted"),
        default="internal",
    )
    publish.set_defaults(handler=command_publish)

    sync = commands.add_parser(
        "sync",
        help="Flush the outbox, receive requests, and quarantine Context Pack responses.",
    )
    sync.add_argument("--project", required=True)
    sync.add_argument("--ledger-project", required=True)
    sync.set_defaults(handler=command_sync)

    run = commands.add_parser(
        "run", help="Keep transport synchronization running on a fixed interval."
    )
    run.add_argument("--project", required=True)
    run.add_argument("--ledger-project", required=True)
    run.add_argument("--interval-seconds", type=int, default=DEFAULT_SYNC_INTERVAL)
    run.add_argument("--retry-min-seconds", type=int, default=DEFAULT_RETRY_MIN_SECONDS)
    run.add_argument("--retry-max-seconds", type=int, default=DEFAULT_RETRY_MAX_SECONDS)
    run.add_argument("--publish-head", action="store_true")
    run.add_argument(
        "--audience", choices=("team", "project-agents"), default="project-agents"
    )
    run.add_argument("--purpose", default="Scheduled project checkpoint")
    run.add_argument(
        "--max-sensitivity",
        choices=("public", "internal", "confidential", "restricted"),
        default="internal",
    )
    run.add_argument("--iterations", type=int, default=0, help=argparse.SUPPRESS)
    run.set_defaults(handler=command_run)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        args.handler(args)
    except (ConnectorError, OSError, SecurityError, ValueError) as failure:
        print(json.dumps({"error": str(failure)}))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
