from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from context_security import (  # noqa: E402
    create_identity_assertion,
    identity_principal,
    load_or_create_identity,
)
import network_bridge as bridge  # noqa: E402
import team_hub as hub  # noqa: E402


class TeamHubTests(unittest.TestCase):
    def setUp(self) -> None:
        # Load the repository-pinned crypto before each isolated bridge home hides
        # the normal private dependency location.
        bridge.crypto_imports()
        self.previous_home = os.environ.get("BRAID_HOME")
        self.previous_disable_keychain = os.environ.get("BRAID_DISABLE_KEYCHAIN")
        os.environ["BRAID_DISABLE_KEYCHAIN"] = "1"

    def tearDown(self) -> None:
        if self.previous_home is None:
            os.environ.pop("BRAID_HOME", None)
        else:
            os.environ["BRAID_HOME"] = self.previous_home
        if self.previous_disable_keychain is None:
            os.environ.pop("BRAID_DISABLE_KEYCHAIN", None)
        else:
            os.environ["BRAID_DISABLE_KEYCHAIN"] = self.previous_disable_keychain

    @staticmethod
    def enrollment_request(
        code_text: str, identity_path: Path, mailbox_public_text: str | None = None
    ) -> tuple[dict[str, object], str, str]:
        identity = load_or_create_identity(identity_path)
        if mailbox_public_text is None:
            _, mailbox_public = bridge.generate_exchange_keypair()
            mailbox_public_text = bridge.b64e(mailbox_public)
        code = hub.decode_enrollment_code(code_text)
        subject = {
            "action": "team-hub-enroll",
            "project_id": code["project_id"],
            "server_principal": code["server_principal"],
            "mailbox_public_key": mailbox_public_text,
            "secret_digest": hashlib.sha256(
                str(code["secret"]).encode("ascii")
            ).hexdigest(),
            "expires_at": code["expires_at"],
        }
        binding_subject = {
            "action": "team-hub-mailbox-binding",
            "project_id": code["project_id"],
            "server_principal": code["server_principal"],
            "mailbox_public_key": mailbox_public_text,
        }
        return (
            {
                "code": code_text,
                "mailbox_public_key": mailbox_public_text,
                "identity": create_identity_assertion(identity, subject),
                "mailbox_binding": create_identity_assertion(identity, binding_subject),
            },
            identity_principal(identity),
            mailbox_public_text,
        )

    @staticmethod
    def authenticated_request(
        identity_path: Path,
        path: str,
        body: dict[str, object],
        *,
        nonce: str = "a" * 32,
        timestamp: int | None = None,
    ) -> dict[str, object]:
        identity = load_or_create_identity(identity_path)
        timestamp = int(time.time()) if timestamp is None else timestamp
        subject = {
            "action": "team-hub-request",
            "path": path,
            "body_sha256": hashlib.sha256(hub._canonical(body)).hexdigest(),
            "timestamp": timestamp,
            "nonce": nonce,
        }
        return {
            "format": hub.REQUEST_FORMAT,
            "body": body,
            "auth": {
                "timestamp": timestamp,
                "nonce": nonce,
                "identity": create_identity_assertion(identity, subject),
            },
        }

    @staticmethod
    def envelope(
        project_id: str,
        sender: str,
        recipient: str,
        *,
        message_id: str = "message_001",
        ciphertext: bytes = b"x" * 32,
    ) -> dict[str, object]:
        now = int(time.time())
        return {
            "format": hub.ENVELOPE_FORMAT,
            "message_id": message_id,
            "project_id": project_id,
            "sender": sender,
            "recipient": recipient,
            "kind": "context-pack",
            "created_at": now,
            "expires_at": now + 3600,
            "ephemeral_public_key": bridge.b64e(b"e" * 32),
            "nonce": bridge.b64e(b"n" * 12),
            "ciphertext": bridge.b64e(ciphertext),
        }

    def test_initialize_is_idempotent_and_enrollment_is_identity_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["BRAID_HOME"] = directory
            store = hub.HubStore(Path(directory) / "hub")
            first = store.initialize("Team Omni", "Phoenix")
            second = store.initialize("Team Omni", "Phoenix")
            self.assertEqual(first["team_id"], second["team_id"])
            self.assertEqual(first["project_id"], second["project_id"])
            enrollment = store.create_enrollment(
                str(first["project_id"]),
                "Alice",
                "member",
                "http://127.0.0.1:8787",
            )
            request, principal, mailbox_key = self.enrollment_request(
                str(enrollment["code"]), Path(directory) / "alice.json"
            )
            accepted = store.redeem_enrollment(request)
            self.assertEqual(accepted["principal"], principal)
            self.assertEqual(accepted["project_id"], first["project_id"])
            self.assertEqual(store.redeem_enrollment(request), accepted)
            directory_result = store.directory(
                principal, {"project_id": first["project_id"]}
            )
            self.assertEqual(directory_result["endpoints"][0]["label"], "Alice")
            self.assertEqual(
                directory_result["endpoints"][0]["mailbox_public_key"], mailbox_key
            )
            disabled = store.set_endpoint_status(principal, "disabled")
            self.assertEqual(disabled["status"], "disabled")
            with self.assertRaisesRegex(hub.HubError, "not a project member"):
                store.directory(principal, {"project_id": first["project_id"]})
            self.assertEqual(
                store.set_endpoint_status(principal, "active")["previous"],
                "disabled",
            )

    def test_used_enrollment_rejects_another_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["BRAID_HOME"] = directory
            store = hub.HubStore(Path(directory) / "hub")
            project = store.initialize("Team Omni", "Phoenix")
            enrollment = store.create_enrollment(
                str(project["project_id"]),
                "Developer",
                "member",
                "http://localhost:8787",
            )
            first, _, _ = self.enrollment_request(
                str(enrollment["code"]), Path(directory) / "one.json"
            )
            second, _, _ = self.enrollment_request(
                str(enrollment["code"]), Path(directory) / "two.json"
            )
            store.redeem_enrollment(first)
            with self.assertRaisesRegex(hub.HubError, "already used"):
                store.redeem_enrollment(second)

    def test_existing_membership_cannot_be_silently_elevated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["BRAID_HOME"] = directory
            store = hub.HubStore(Path(directory) / "hub")
            project = store.initialize("Team Omni", "Phoenix")
            identity_path = Path(directory) / "alice.json"
            member = store.create_enrollment(
                str(project["project_id"]),
                "Alice",
                "member",
                "http://localhost:8787",
            )
            request, principal, _ = self.enrollment_request(
                str(member["code"]), identity_path
            )
            store.redeem_enrollment(request)
            elevated = store.create_enrollment(
                str(project["project_id"]),
                "Alice",
                "project-agent",
                "http://localhost:8787",
            )
            elevated_request, elevated_principal, _ = self.enrollment_request(
                str(elevated["code"]), identity_path, str(request["mailbox_public_key"])
            )
            self.assertEqual(elevated_principal, principal)
            with self.assertRaisesRegex(hub.HubError, "different role"):
                store.redeem_enrollment(elevated_request)

    def test_signed_request_replay_staleness_and_tamper_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["BRAID_HOME"] = directory
            identity_path = Path(directory) / "alice.json"
            store = hub.HubStore(Path(directory) / "hub")
            project = store.initialize("Team Omni", "Phoenix")
            enrollment = store.create_enrollment(
                str(project["project_id"]),
                "Alice",
                "member",
                "http://localhost:8787",
            )
            request, principal, _ = self.enrollment_request(
                str(enrollment["code"]), identity_path
            )
            store.redeem_enrollment(request)
            body = {"project_id": project["project_id"]}
            signed = self.authenticated_request(identity_path, "/v1/status", body)
            self.assertEqual(store.authenticate("/v1/status", signed)[0], principal)
            with self.assertRaisesRegex(hub.HubError, "nonce was reused"):
                store.authenticate("/v1/status", signed)
            stale = self.authenticated_request(
                identity_path,
                "/v1/status",
                body,
                nonce="b" * 32,
                timestamp=int(time.time()) - hub.REQUEST_WINDOW_SECONDS - 1,
            )
            with self.assertRaisesRegex(hub.HubError, "outside the window"):
                store.authenticate("/v1/status", stale)
            tampered = self.authenticated_request(
                identity_path, "/v1/status", body, nonce="c" * 32
            )
            tampered["body"] = {"project_id": "project_tampered"}
            with self.assertRaisesRegex(hub.HubError, "subject mismatch"):
                store.authenticate("/v1/status", tampered)

    def test_offline_delivery_is_idempotent_and_ack_erases_ciphertext(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["BRAID_HOME"] = directory
            store = hub.HubStore(Path(directory) / "hub")
            project = store.initialize("Team Omni", "Phoenix")
            principals: list[str] = []
            for label in ("Alice", "Bob"):
                enrollment = store.create_enrollment(
                    str(project["project_id"]),
                    label,
                    "member",
                    "http://127.0.0.1:8787",
                )
                request, principal, _ = self.enrollment_request(
                    str(enrollment["code"]), Path(directory) / f"{label}.json"
                )
                store.redeem_enrollment(request)
                principals.append(principal)
            alice, bob = principals
            envelope = self.envelope(str(project["project_id"]), alice, bob)
            pushed = store.push(alice, {"envelope": envelope})
            self.assertFalse(pushed["idempotent"])
            retried = store.push(alice, {"envelope": envelope})
            self.assertTrue(retried["idempotent"])
            altered = self.envelope(
                str(project["project_id"]),
                alice,
                bob,
                ciphertext=b"y" * 32,
            )
            with self.assertRaisesRegex(hub.HubError, "another envelope"):
                store.push(alice, {"envelope": altered})
            second_envelope = self.envelope(
                str(project["project_id"]),
                alice,
                bob,
                message_id="message_002",
            )
            with mock.patch.object(hub, "MAX_PENDING_MESSAGES", 1):
                with self.assertRaisesRegex(hub.HubError, "capacity"):
                    store.push(alice, {"envelope": second_envelope})
            with self.assertRaisesRegex(hub.HubError, "Invalid message ID"):
                store.acknowledge(
                    bob,
                    {
                        "project_id": project["project_id"],
                        "message_ids": [{}],
                    },
                )
            page = store.pull(
                bob, {"project_id": project["project_id"], "after": 0, "limit": 10}
            )
            self.assertEqual(len(page["messages"]), 1)
            self.assertEqual(page["messages"][0]["envelope"], envelope)
            acknowledged = store.acknowledge(
                bob,
                {
                    "project_id": project["project_id"],
                    "message_ids": [envelope["message_id"]],
                },
            )
            self.assertEqual(acknowledged["acknowledged"], ["message_001"])
            repeated = store.acknowledge(
                bob,
                {
                    "project_id": project["project_id"],
                    "message_ids": [envelope["message_id"]],
                },
            )
            self.assertEqual(repeated["already_acknowledged"], ["message_001"])
            self.assertEqual(
                store.pull(
                    bob,
                    {"project_id": project["project_id"], "after": 0, "limit": 10},
                )["messages"],
                [],
            )
            with closing(sqlite3.connect(store.database)) as connection:
                row = connection.execute(
                    "SELECT state, envelope FROM messages WHERE message_id = ?",
                    ("message_001",),
                ).fetchone()
            self.assertEqual(row, ("acked", None))
            future = int(time.time()) + hub.RECEIPT_RETENTION_SECONDS + 1
            with mock.patch.object(hub, "_now", return_value=future):
                self.assertEqual(store.purge()["deleted_receipts"], 1)

    def test_project_membership_prevents_cross_project_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["BRAID_HOME"] = directory
            store = hub.HubStore(Path(directory) / "hub")
            first = store.initialize("Team Omni", "Phoenix")
            second = store.initialize("Team Omni", "Atlas")
            principals: list[str] = []
            for index, project in enumerate((first, second)):
                enrollment = store.create_enrollment(
                    str(project["project_id"]),
                    f"Developer {index}",
                    "member",
                    "http://localhost:8787",
                )
                request, principal, _ = self.enrollment_request(
                    str(enrollment["code"]), Path(directory) / f"dev-{index}.json"
                )
                store.redeem_enrollment(request)
                principals.append(principal)
            envelope = self.envelope(
                str(first["project_id"]), principals[0], principals[1]
            )
            with self.assertRaisesRegex(hub.HubError, "not a project member"):
                store.push(principals[0], {"envelope": envelope})

    def test_expiry_purges_payload_and_audit_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["BRAID_HOME"] = directory
            store = hub.HubStore(Path(directory) / "hub")
            project = store.initialize("Team Omni", "Phoenix")
            principals: list[str] = []
            for label in ("Alice", "Bob"):
                enrollment = store.create_enrollment(
                    str(project["project_id"]),
                    label,
                    "member",
                    "http://localhost:8787",
                )
                request, principal, _ = self.enrollment_request(
                    str(enrollment["code"]), Path(directory) / f"{label}.json"
                )
                store.redeem_enrollment(request)
                principals.append(principal)
            now = int(time.time())
            with mock.patch.object(hub, "_now", return_value=now):
                envelope = self.envelope(
                    str(project["project_id"]), principals[0], principals[1]
                )
                envelope["created_at"] = now
                envelope["expires_at"] = now + 1
                store.push(principals[0], {"envelope": envelope})
            with mock.patch.object(hub, "_now", return_value=now + 2):
                self.assertEqual(store.purge()["expired_messages"], 1)
            with closing(sqlite3.connect(store.database)) as connection:
                row = connection.execute(
                    "SELECT state, envelope FROM messages WHERE message_id = ?",
                    ("message_001",),
                ).fetchone()
            self.assertEqual(row, ("expired", None))
            self.assertTrue(store.verify_audit()["valid"])
            with closing(sqlite3.connect(store.database)) as connection:
                connection.execute(
                    "UPDATE audit SET details = ? WHERE sequence = 1",
                    (json.dumps({"tampered": True}),),
                )
                connection.commit()
            with self.assertRaisesRegex(hub.HubError, "audit chain is invalid"):
                store.verify_audit()

    def test_public_plaintext_enrollment_url_is_rejected(self) -> None:
        with self.assertRaisesRegex(hub.HubError, "must use HTTPS"):
            hub._validate_server_url("http://example.com")
        self.assertEqual(
            hub._validate_server_url("http://127.0.0.1:8787"),
            "http://127.0.0.1:8787",
        )
        self.assertEqual(
            hub._validate_server_url("https://bridge.example.com"),
            "https://bridge.example.com",
        )

    def test_rate_limiter_is_bounded_and_recovers_after_window(self) -> None:
        limiter = hub.HubRateLimiter(maximum_keys=2)
        with mock.patch.object(hub.time, "monotonic", return_value=100.0):
            self.assertTrue(limiter.allow("one", 2, 10))
            self.assertTrue(limiter.allow("one", 2, 10))
            self.assertFalse(limiter.allow("one", 2, 10))
            self.assertTrue(limiter.allow("two", 2, 10))
            self.assertTrue(limiter.allow("three", 2, 10))
            self.assertLessEqual(len(limiter._events), 2)
        with mock.patch.object(hub.time, "monotonic", return_value=111.0):
            self.assertTrue(limiter.allow("one", 2, 10))

    def test_concurrent_pushes_are_durable_and_duplicate_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["BRAID_HOME"] = directory
            store = hub.HubStore(Path(directory) / "hub")
            project = store.initialize("Team Omni", "Phoenix")
            principals: list[str] = []
            for label in ("Alice", "Bob"):
                enrollment = store.create_enrollment(
                    str(project["project_id"]),
                    label,
                    "member",
                    "http://localhost:8787",
                )
                request, principal, _ = self.enrollment_request(
                    str(enrollment["code"]), Path(directory) / f"{label}.json"
                )
                store.redeem_enrollment(request)
                principals.append(principal)
            alice, bob = principals
            envelopes = [
                self.envelope(
                    str(project["project_id"]),
                    alice,
                    bob,
                    message_id=f"concurrent_{index:03d}",
                )
                for index in range(32)
            ]
            with ThreadPoolExecutor(max_workers=16) as pool:
                results = list(
                    pool.map(
                        lambda value: store.push(alice, {"envelope": value}), envelopes
                    )
                )
            self.assertEqual(len(results), 32)
            self.assertTrue(all(not result["idempotent"] for result in results))
            page = store.pull(
                bob, {"project_id": project["project_id"], "after": 0, "limit": 64}
            )
            self.assertEqual(len(page["messages"]), 32)

            duplicate = self.envelope(
                str(project["project_id"]),
                alice,
                bob,
                message_id="duplicate_concurrent",
            )
            with ThreadPoolExecutor(max_workers=16) as pool:
                duplicate_results = list(
                    pool.map(
                        lambda _index: store.push(alice, {"envelope": duplicate}),
                        range(16),
                    )
                )
            self.assertEqual(
                sum(not result["idempotent"] for result in duplicate_results), 1
            )


if __name__ == "__main__":
    unittest.main()
