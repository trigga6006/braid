"""Repeatable concurrent mailbox benchmark for the self-hosted Team Hub."""

from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from context_security import (  # noqa: E402
    create_identity_assertion,
    identity_principal,
    load_or_create_identity,
)
import network_bridge as bridge  # noqa: E402
import team_hub as hub  # noqa: E402


def _enroll(store: hub.HubStore, project_id: str, root: Path, label: str) -> str:
    created = store.create_enrollment(
        project_id, label, "member", "http://127.0.0.1:8787"
    )
    code = hub.decode_enrollment_code(str(created["code"]))
    identity = load_or_create_identity(root / f"{label.lower()}.json")
    _, mailbox_public = bridge.generate_exchange_keypair()
    mailbox_public_text = base64.urlsafe_b64encode(mailbox_public).decode().rstrip("=")
    subject = {
        "action": "team-hub-enroll",
        "project_id": project_id,
        "server_principal": code["server_principal"],
        "mailbox_public_key": mailbox_public_text,
        "secret_digest": hashlib.sha256(
            str(code["secret"]).encode("ascii")
        ).hexdigest(),
        "expires_at": code["expires_at"],
    }
    binding_subject = {
        "action": "team-hub-mailbox-binding",
        "project_id": project_id,
        "server_principal": code["server_principal"],
        "mailbox_public_key": mailbox_public_text,
    }
    store.redeem_enrollment(
        {
            "code": created["code"],
            "mailbox_public_key": mailbox_public_text,
            "identity": create_identity_assertion(identity, subject),
            "mailbox_binding": create_identity_assertion(identity, binding_subject),
        }
    )
    return identity_principal(identity)


def _envelope(
    project_id: str, sender: str, recipient: str, index: int, payload_bytes: int
) -> dict[str, Any]:
    now = int(time.time())
    return {
        "format": hub.ENVELOPE_FORMAT,
        "message_id": f"benchmark_{index:08d}",
        "project_id": project_id,
        "sender": sender,
        "recipient": recipient,
        "kind": "context-pack",
        "created_at": now,
        "expires_at": now + 3600,
        "ephemeral_public_key": bridge.b64e(b"e" * 32),
        "nonce": bridge.b64e(b"n" * 12),
        "ciphertext": bridge.b64e(b"x" * max(17, payload_bytes)),
    }


def run(messages: int, workers: int, payload_bytes: int) -> dict[str, Any]:
    if messages < 1 or messages > hub.MAX_PENDING_MESSAGES:
        raise ValueError("messages must fit one Team Hub mailbox")
    if workers < 1 or workers > 64:
        raise ValueError("workers must be between 1 and 64")
    # Resolve the repository-pinned crypto before the isolated benchmark home
    # intentionally hides the user's normal Session Bridge dependency cache.
    bridge.crypto_imports()
    with tempfile.TemporaryDirectory(prefix="session-bridge-team-hub-") as directory:
        root = Path(directory)
        previous_home = os.environ.get("SESSION_BRIDGE_HOME")
        previous_keychain = os.environ.get("SESSION_BRIDGE_DISABLE_KEYCHAIN")
        os.environ["SESSION_BRIDGE_HOME"] = str(root / "security")
        os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = "1"
        try:
            store = hub.HubStore(root / "hub")
            project = store.initialize("Benchmark Team", "Benchmark Project")
            project_id = str(project["project_id"])
            sender = _enroll(store, project_id, root, "Sender")
            recipient = _enroll(store, project_id, root, "Recipient")
            envelopes = [
                _envelope(project_id, sender, recipient, index, payload_bytes)
                for index in range(messages)
            ]
            push_started = time.perf_counter()
            with ThreadPoolExecutor(max_workers=workers) as pool:
                pushed = list(
                    pool.map(
                        lambda value: store.push(sender, {"envelope": value}),
                        envelopes,
                    )
                )
            push_seconds = time.perf_counter() - push_started

            pull_started = time.perf_counter()
            cursor = 0
            received: list[dict[str, Any]] = []
            while True:
                page = store.pull(
                    recipient,
                    {"project_id": project_id, "after": cursor, "limit": hub.MAX_PAGE},
                )
                if not page["messages"]:
                    break
                received.extend(page["messages"])
                cursor = int(page["messages"][-1]["sequence"])
                if not page["has_more"]:
                    break
            pull_seconds = time.perf_counter() - pull_started

            ack_started = time.perf_counter()
            message_ids = [str(item["envelope"]["message_id"]) for item in received]
            for offset in range(0, len(message_ids), hub.MAX_PAGE):
                store.acknowledge(
                    recipient,
                    {
                        "project_id": project_id,
                        "message_ids": message_ids[offset : offset + hub.MAX_PAGE],
                    },
                )
            ack_seconds = time.perf_counter() - ack_started
            database_bytes = sum(
                path.stat().st_size
                for path in (
                    store.database,
                    store.database.with_name(store.database.name + "-wal"),
                )
                if path.exists()
            )
            audit = store.verify_audit()
            return {
                "format": "session-bridge-team-hub-benchmark/v1",
                "environment": {
                    "python": platform.python_version(),
                    "platform": platform.platform(),
                },
                "messages": messages,
                "workers": workers,
                "payload_bytes": payload_bytes,
                "push_seconds": round(push_seconds, 6),
                "push_messages_per_second": round(messages / push_seconds, 2),
                "pull_seconds": round(pull_seconds, 6),
                "ack_seconds": round(ack_seconds, 6),
                "database_bytes_after_ack": database_bytes,
                "all_unique_pushes": all(not item["idempotent"] for item in pushed),
                "received": len(received),
                "audit_valid": bool(audit["valid"]),
            }
        finally:
            if previous_home is None:
                os.environ.pop("SESSION_BRIDGE_HOME", None)
            else:
                os.environ["SESSION_BRIDGE_HOME"] = previous_home
            if previous_keychain is None:
                os.environ.pop("SESSION_BRIDGE_DISABLE_KEYCHAIN", None)
            else:
                os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = previous_keychain


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--messages", type=int, default=250)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--payload-bytes", type=int, default=4096)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = run(args.messages, args.workers, args.payload_bytes)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
