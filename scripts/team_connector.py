"""Endpoint connector for the self-hosted asynchronous Session Bridge Team Hub."""

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
import network_bridge as bridge
import team_hub as hub


CONNECTOR_FORMAT = "session-bridge-team-connector/v1"
MAILBOX_IDENTITY_FORMAT = "session-bridge-mailbox-identity/v1"
MAX_RESPONSE_BYTES = 2_000_000
DEFAULT_SYNC_INTERVAL = 12 * 3600
DEFAULT_RETRY_MIN_SECONDS = 5
DEFAULT_RETRY_MAX_SECONDS = 300
MAX_SYNC_PAGES = 100


class ConnectorError(ValueError):
    """Safe endpoint-side failure."""


class TransientConnectorError(ConnectorError):
    """Connectivity or server-pressure failure that an always-on loop may retry."""


@dataclass(frozen=True)
class MailboxIdentity:
    public_key: bytes
    private_key: bytes


def connector_home(explicit: Path | None = None) -> Path:
    if explicit is not None:
        return explicit.expanduser().resolve()
    return (
        Path(os.environ.get("SESSION_BRIDGE_HOME", Path.home() / ".session-bridge"))
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
        info=b"session-bridge/team-mailbox/v1",
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
    if ttl_seconds < 1 or ttl_seconds > hub.MAX_MESSAGE_TTL_SECONDS:
        raise ConnectorError("Mailbox message lifetime is invalid.")
    private, ephemeral_public = bridge.generate_exchange_keypair()
    key = _mailbox_key(private, recipient_mailbox_key, project_id, sender, recipient)
    now = int(time.time())
    inner_expiry = int(bundle["export"]["expires_at"])
    message_id = "msg_" + secrets.token_hex(16)
    header = {
        "format": hub.ENVELOPE_FORMAT,
        "message_id": message_id,
        "project_id": project_id,
        "sender": sender,
        "recipient": recipient,
        "kind": "context-pack",
        "created_at": now,
        "expires_at": min(now + ttl_seconds, inner_expiry),
        "ephemeral_public_key": _b64e(ephemeral_public),
    }
    if header["expires_at"] <= now:
        raise ConnectorError("Context Pack has already expired.")
    plaintext = canonical_bytes(dict(bundle))
    if len(plaintext) > hub.MAX_ENVELOPE_BYTES - 4096:
        raise ConnectorError("Context Pack is too large for a Team Hub envelope.")
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
    if envelope.get("kind") != "context-pack":
        raise ConnectorError("Mailbox envelope is not a Context Pack.")
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
        bundle = strict_json_loads(plaintext)
    except SecurityError as error:
        raise ConnectorError("Decrypted Context Pack is invalid.") from error
    if not isinstance(bundle, dict):
        raise ConnectorError("Decrypted Context Pack must be an object.")
    try:
        bridge.validate_disclosure_bundle(bundle, expected_recipient)
    except ValueError as error:
        raise ConnectorError(str(error)) from error
    return bundle


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

    def _post(self, path: str, value: Mapping[str, Any]) -> dict[str, Any]:
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
            try:
                parsed = strict_json_loads(raw_error)
                message = parsed["error"]["message"]
            except (SecurityError, KeyError, TypeError):
                message = f"Team Hub returned HTTP {failure.code}."
            failure_type = (
                TransientConnectorError
                if failure.code in {408, 425, 429} or failure.code >= 500
                else ConnectorError
            )
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
            self._post(path, wrapper),
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

    def queue_bundle(
        self, alias: str, bundle_path: Path, ttl_seconds: int
    ) -> dict[str, Any]:
        config = self.load_config(alias)
        bundle = _read_json(bundle_path, hub.MAX_ENVELOPE_BYTES)
        try:
            recipient = str(bundle["export"]["recipient"])
        except (KeyError, TypeError) as error:
            raise ConnectorError("Context Pack recipient is missing.") from error
        directory = self.directory(alias)
        matches = [
            endpoint
            for endpoint in directory.get("endpoints", [])
            if isinstance(endpoint, dict) and endpoint.get("principal") == recipient
        ]
        if len(matches) != 1:
            raise ConnectorError(
                "Context Pack recipient is not an active project endpoint."
            )
        if matches[0].get("trust") != "trusted":
            raise ConnectorError(
                "Context Pack recipient is not locally trusted; compare its principal "
                "through a trusted channel and run the trust command first."
            )
        mailbox_public = _b64d(matches[0].get("mailbox_public_key"), 64)
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
        outbox = self.home / "team-outbox" / _safe_alias(alias)
        path = outbox / f"{envelope['message_id']}.json"
        bridge.save_protected_json(path, {"envelope": envelope})
        return {
            "queued": True,
            "message_id": envelope["message_id"],
            "recipient": recipient,
            "outbox": str(path),
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

    def flush(self, alias: str) -> list[dict[str, Any]]:
        config = self.load_config(alias)
        outbox = self.home / "team-outbox" / _safe_alias(alias)
        results: list[dict[str, Any]] = []
        for path in sorted(outbox.glob("*.json")) if outbox.exists() else []:
            record = bridge.load_protected_json(path)
            envelope = record.get("envelope")
            if not isinstance(envelope, dict):
                raise ConnectorError(f"Invalid outbox entry: {path.name}")
            result = self.client(config).authenticated(
                "/v1/mailbox/push",
                {"envelope": envelope},
                self.identity_path,
            )
            if result.get("message_id") != envelope.get("message_id"):
                raise ConnectorError("Team Hub acknowledged another message.")
            path.unlink()
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
        rejected: list[dict[str, Any]] = []
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
            raise ConnectorError("Team Hub sync page limit was exceeded.")
        return {
            "project": alias,
            "cursor": cursor,
            "quarantined": quarantined,
            "rejected": rejected,
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
    parser.add_argument("--home", type=Path, help="Endpoint Session Bridge state root.")
    parser.add_argument("--version", action="version", version="%(prog)s 0.4.0")
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
        help="Flush the outbox and quarantine all available inbound Context Packs.",
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
