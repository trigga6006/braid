from __future__ import annotations

from contextlib import closing, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from context_model import make_claim  # noqa: E402
from context_store import ContextLedger  # noqa: E402
import network_bridge as bridge  # noqa: E402
import team_connector as connector  # noqa: E402
import team_hub as hub  # noqa: E402


def committed_revision(ledger: ContextLedger) -> dict[str, object]:
    stage = ledger.stage(
        [
            make_claim(
                "claim-team-sync",
                "decision",
                "Use the asynchronous Team Hub mailbox.",
                "team-hub-transport",
                [
                    {
                        "type": "test_result",
                        "uri": "test:team-connector",
                        "digest": "sha256:" + "a" * 64,
                        "observed_at": "2026-07-22T00:00:00Z",
                    }
                ],
                observed_at="2026-07-22T00:00:00Z",
            )
        ],
        "team connector test",
    )
    review = ledger.review_staged(stage["stage_id"])
    ledger.approve_staged(stage["stage_id"], review["review_digest"])
    return ledger.commit("alice", stage_id=stage["stage_id"])


def committed_blocker(ledger: ContextLedger) -> dict[str, object]:
    stage = ledger.stage(
        [
            make_claim(
                "claim-auth-blocker",
                "blocker",
                "The callback allowlist is missing the production origin.",
                "auth-callback",
                [
                    {
                        "type": "test_result",
                        "uri": "test:auth-callback",
                        "digest": "sha256:" + "b" * 64,
                        "observed_at": "2026-07-22T01:00:00Z",
                    }
                ],
                labels=["backend", "authentication"],
                observed_at="2026-07-22T01:00:00Z",
            )
        ],
        "new authentication blocker",
    )
    review = ledger.review_staged(stage["stage_id"])
    ledger.approve_staged(stage["stage_id"], review["review_digest"])
    return ledger.commit("bob", stage_id=stage["stage_id"])


def committed_retraction(ledger: ContextLedger) -> dict[str, object]:
    claim = make_claim(
        "claim-team-sync",
        "decision",
        "Use the asynchronous Team Hub mailbox.",
        "team-hub-transport",
        [
            {
                "type": "test_result",
                "uri": "test:team-connector-retraction",
                "digest": "sha256:" + "c" * 64,
                "observed_at": "2026-07-22T02:00:00Z",
            }
        ],
        observed_at="2026-07-22T02:00:00Z",
    )
    claim["status"] = "retracted"
    stage = ledger.stage([claim], "retract the earlier transport decision")
    review = ledger.review_staged(stage["stage_id"])
    ledger.approve_staged(stage["stage_id"], review["review_digest"])
    return ledger.commit("bob", stage_id=stage["stage_id"])


class ConnectorHarness:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.store = hub.HubStore(root / "hub")
        self.server = hub.BoundedHubServer(("127.0.0.1", 0), hub.HubHandler)
        self.server.store = self.store
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.project = self.store.initialize("Team Omni", "Phoenix")

    def enroll(
        self, label: str, endpoint_home: Path, role: str = "member"
    ) -> connector.TeamConnector:
        enrollment = self.store.create_enrollment(
            str(self.project["project_id"]), label, role, self.url
        )
        code = endpoint_home / "enrollment-code.txt"
        code.parent.mkdir(parents=True, exist_ok=True)
        code.write_text(str(enrollment["code"]), encoding="utf-8")
        endpoint = connector.TeamConnector(endpoint_home)
        endpoint.enroll("phoenix", code.read_text(encoding="utf-8"))
        code.unlink()
        return endpoint

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class TeamConnectorTests(unittest.TestCase):
    def setUp(self) -> None:
        bridge.crypto_imports()
        self.previous_home = os.environ.get("SESSION_BRIDGE_HOME")
        self.previous_disable_keychain = os.environ.get(
            "SESSION_BRIDGE_DISABLE_KEYCHAIN"
        )
        os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = "1"

    def tearDown(self) -> None:
        if self.previous_home is None:
            os.environ.pop("SESSION_BRIDGE_HOME", None)
        else:
            os.environ["SESSION_BRIDGE_HOME"] = self.previous_home
        if self.previous_disable_keychain is None:
            os.environ.pop("SESSION_BRIDGE_DISABLE_KEYCHAIN", None)
        else:
            os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = (
                self.previous_disable_keychain
            )

    def test_offline_signed_context_pack_reaches_receiver_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.environ["SESSION_BRIDGE_HOME"] = str(root / "shared-security")
            harness = ConnectorHarness(root)
            try:
                alice = harness.enroll("Alice", root / "alice")
                bob = harness.enroll("Bob", root / "bob")
                bob_config = bob.load_config("phoenix")
                alice.trust("phoenix", str(bob_config["principal"]))
                bob.trust("phoenix", str(alice.load_config("phoenix")["principal"]))
                alice_ledger = ContextLedger("phoenix", root / "alice")
                revision = committed_revision(alice_ledger)
                bundle = root / "alice-to-bob.json"
                alice_ledger.export(
                    str(revision["id"]),
                    bundle,
                    recipient=str(bob_config["principal"]),
                    purpose="daily project checkpoint",
                )
                queued = alice.queue_bundle("phoenix", bundle, 3600)
                bundle.unlink()
                self.assertTrue(queued["queued"])
                sent = alice.flush("phoenix")
                self.assertEqual(sent[0]["state"], "pending")
                self.assertEqual(
                    bob.status("phoenix")["remote"]["mailbox"]["pending"], 1
                )
                received = bob.sync("phoenix", "phoenix")
                self.assertEqual(len(received["quarantined"]), 1)
                self.assertEqual(received["rejected"], [])
                token = received["quarantined"][0]["quarantine_token"]
                review = ContextLedger("phoenix", root / "bob").review_import(token)
                self.assertEqual(review["recipient"], bob_config["principal"])
                self.assertEqual(review["claim_count"], 1)
                self.assertEqual(
                    review["claims"][0]["statement"],
                    "Use the asynchronous Team Hub mailbox.",
                )
                self.assertEqual(bob.status("phoenix")["remote"]["mailbox"]["acked"], 1)
                with closing(sqlite3.connect(harness.store.database)) as connection:
                    stored = connection.execute(
                        "SELECT state, envelope FROM messages"
                    ).fetchone()
                self.assertEqual(stored, ("acked", None))
            finally:
                harness.close()

    def test_context_pull_request_returns_only_bounded_semantic_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.environ["SESSION_BRIDGE_HOME"] = str(root / "shared-security")
            harness = ConnectorHarness(root)
            try:
                alice = harness.enroll("Alice", root / "alice")
                bob = harness.enroll("Bob", root / "bob")
                alice_config = alice.load_config("phoenix")
                bob_config = bob.load_config("phoenix")
                alice.trust("phoenix", str(bob_config["principal"]))
                bob.trust("phoenix", str(alice_config["principal"]))

                bob_ledger = ContextLedger("phoenix", root / "bob")
                checkpoint = committed_revision(bob_ledger)
                committed_blocker(bob_ledger)

                queued = alice.queue_request(
                    "phoenix",
                    recipient=str(bob_config["principal"]),
                    purpose="authentication handoff",
                    question="Which authentication blockers changed?",
                    kinds=["blocker"],
                    labels=["backend"],
                    since_revision=str(checkpoint["id"]),
                    max_sensitivity="internal",
                    max_claims=1,
                    max_bytes=50_000,
                )
                alice.flush("phoenix")
                received_by_bob = bob.sync("phoenix", "phoenix")
                self.assertEqual(len(received_by_bob["requests"]), 1)
                self.assertEqual(received_by_bob["quarantined"], [])
                self.assertEqual(received_by_bob["rejected"], [])

                listed = bob.requests("phoenix")["requests"]
                inbound = next(
                    item for item in listed if item["direction"] == "inbound"
                )
                self.assertEqual(inbound["state"], "open")
                self.assertEqual(inbound["selectors"]["kinds"], ["blocker"])

                response = bob.respond(
                    "phoenix",
                    "phoenix",
                    str(queued["request_id"]),
                )
                self.assertEqual(response["status"], "fulfilled")
                self.assertEqual(response["claim_ids"], ["claim-auth-blocker"])
                with self.assertRaisesRegex(
                    connector.ConnectorError, "already has a final response"
                ):
                    bob.respond(
                        "phoenix",
                        "phoenix",
                        str(queued["request_id"]),
                    )

                bob.flush("phoenix")
                received_by_alice = alice.sync("phoenix", "phoenix")
                self.assertEqual(
                    len(received_by_alice["responses"]), 1, received_by_alice
                )
                self.assertEqual(
                    received_by_alice["responses"][0]["status"], "fulfilled"
                )
                self.assertEqual(len(received_by_alice["quarantined"]), 1)
                self.assertEqual(received_by_alice["rejected"], [])

                token = received_by_alice["quarantined"][0]["quarantine_token"]
                review = ContextLedger("phoenix", root / "alice").review_import(token)
                self.assertEqual(review["claim_count"], 1)
                self.assertEqual(review["claims"][0]["id"], "claim-auth-blocker")
                self.assertEqual(
                    review["claims"][0]["statement"],
                    "The callback allowlist is missing the production origin.",
                )

                outbound = next(
                    item
                    for item in alice.requests("phoenix")["requests"]
                    if item["direction"] == "outbound"
                )
                self.assertEqual(outbound["state"], "response-received")
                self.assertEqual(outbound["response"]["status"], "fulfilled")
            finally:
                harness.close()

    def test_signed_context_pull_response_cannot_expand_request_selectors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.environ["SESSION_BRIDGE_HOME"] = str(root / "shared-security")
            harness = ConnectorHarness(root)
            try:
                alice = harness.enroll("Alice", root / "alice")
                bob = harness.enroll("Bob", root / "bob")
                alice_config = alice.load_config("phoenix")
                bob_config = bob.load_config("phoenix")
                alice.trust("phoenix", str(bob_config["principal"]))
                bob.trust("phoenix", str(alice_config["principal"]))

                bob_ledger = ContextLedger("phoenix", root / "bob")
                decision_revision = committed_revision(bob_ledger)
                queued = alice.queue_request(
                    "phoenix",
                    recipient=str(bob_config["principal"]),
                    purpose="authentication handoff",
                    question="Which authentication blockers changed?",
                    kinds=["blocker"],
                )
                request_state = bridge.load_protected_json(
                    alice.exchange_state_path(
                        "phoenix", "outbound", str(queued["request_id"])
                    )
                )
                out_of_scope = bob_ledger.disclose(
                    str(alice_config["principal"]),
                    str(decision_revision["id"]),
                    claim_ids=["claim-team-sync"],
                    purpose="authentication handoff",
                )["bundle"]
                response = connector.exchange.create_response(
                    connector.load_or_create_identity(bob.identity_path),
                    request_state["request"],
                    status="fulfilled",
                    bundle=out_of_scope,
                )
                peer = bob._trusted_endpoint("phoenix", str(alice_config["principal"]))
                envelope = connector.seal_mailbox_payload(
                    response,
                    kind="coordination-note",
                    project_id=str(bob_config["project_id"]),
                    sender=str(bob_config["principal"]),
                    recipient=str(alice_config["principal"]),
                    recipient_mailbox_key=connector._b64d(
                        peer["mailbox_public_key"], 64
                    ),
                    ttl_seconds=3600,
                    inner_expires_at=int(response["expires_at"]),
                )
                bob._queue_envelope("phoenix", envelope)
                bob.flush("phoenix")

                received = alice.sync("phoenix", "phoenix")
                self.assertEqual(received["responses"], [])
                self.assertEqual(received["quarantined"], [])
                self.assertEqual(len(received["rejected"]), 1)
                self.assertIn("kind selector", received["rejected"][0]["reason"])
            finally:
                harness.close()

    def test_lifecycle_removal_requests_clarification_instead_of_partial_delta(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.environ["SESSION_BRIDGE_HOME"] = str(root / "shared-security")
            harness = ConnectorHarness(root)
            try:
                alice = harness.enroll("Alice", root / "alice")
                bob = harness.enroll("Bob", root / "bob")
                alice_config = alice.load_config("phoenix")
                bob_config = bob.load_config("phoenix")
                alice.trust("phoenix", str(bob_config["principal"]))
                bob.trust("phoenix", str(alice_config["principal"]))

                bob_ledger = ContextLedger("phoenix", root / "bob")
                checkpoint = committed_revision(bob_ledger)
                committed_retraction(bob_ledger)
                queued = alice.queue_request(
                    "phoenix",
                    recipient=str(bob_config["principal"]),
                    purpose="transport decision handoff",
                    question="Which transport decisions changed?",
                    kinds=["decision"],
                    since_revision=str(checkpoint["id"]),
                )
                alice.flush("phoenix")
                bob.sync("phoenix", "phoenix")

                response = bob.respond("phoenix", "phoenix", str(queued["request_id"]))
                self.assertEqual(response["status"], "needs-clarification")
                self.assertEqual(response["claim_ids"], [])
                bob.flush("phoenix")

                received = alice.sync("phoenix", "phoenix")
                self.assertEqual(received["quarantined"], [])
                self.assertEqual(
                    received["responses"][0]["status"], "needs-clarification"
                )
                self.assertIn("lifecycle removals", received["responses"][0]["note"])
            finally:
                harness.close()

    def test_authenticated_but_tampered_ciphertext_is_rejected_and_acked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.environ["SESSION_BRIDGE_HOME"] = str(root / "shared-security")
            harness = ConnectorHarness(root)
            try:
                alice = harness.enroll("Alice", root / "alice")
                bob = harness.enroll("Bob", root / "bob")
                alice.trust("phoenix", str(bob.load_config("phoenix")["principal"]))
                bob.trust("phoenix", str(alice.load_config("phoenix")["principal"]))
                alice_ledger = ContextLedger("phoenix", root / "alice")
                revision = committed_revision(alice_ledger)
                bundle = root / "bundle.json"
                alice_ledger.export(
                    str(revision["id"]),
                    bundle,
                    recipient=str(bob.load_config("phoenix")["principal"]),
                )
                queued = alice.queue_bundle("phoenix", bundle, 3600)
                outbox_path = Path(str(queued["outbox"]))
                record = bridge.load_protected_json(outbox_path)
                ciphertext = str(record["envelope"]["ciphertext"])
                record["envelope"]["ciphertext"] = (
                    "A" if ciphertext[0] != "A" else "B"
                ) + ciphertext[1:]
                bridge.save_protected_json(outbox_path, record)
                alice.flush("phoenix")
                received = bob.sync("phoenix", "phoenix")
                self.assertEqual(received["quarantined"], [])
                self.assertEqual(len(received["rejected"]), 1)
                rejection = (
                    root
                    / "bob"
                    / "team-rejections"
                    / "phoenix"
                    / f"{queued['message_id']}.json"
                )
                self.assertTrue(rejection.exists())
                value = json.loads(rejection.read_text(encoding="utf-8"))
                self.assertIn("authentication failed", value["reason"])
                self.assertEqual(bob.status("phoenix")["remote"]["mailbox"]["acked"], 1)
            finally:
                harness.close()

    def test_untrusted_sender_is_rejected_before_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.environ["SESSION_BRIDGE_HOME"] = str(root / "shared-security")
            harness = ConnectorHarness(root)
            try:
                alice = harness.enroll("Alice", root / "alice")
                bob = harness.enroll("Bob", root / "bob")
                bob_principal = str(bob.load_config("phoenix")["principal"])
                alice.trust("phoenix", bob_principal)
                alice_ledger = ContextLedger("phoenix", root / "alice")
                revision = committed_revision(alice_ledger)
                bundle = root / "untrusted-sender.json"
                alice_ledger.export(
                    str(revision["id"]), bundle, recipient=bob_principal
                )
                alice.queue_bundle("phoenix", bundle, 3600)
                alice.flush("phoenix")
                received = bob.sync("phoenix", "phoenix")
                self.assertEqual(received["quarantined"], [])
                self.assertEqual(len(received["rejected"]), 1)
                self.assertIn("not locally trusted", received["rejected"][0]["reason"])
                ledger = ContextLedger("phoenix", root / "bob")
                self.assertEqual(list(ledger.quarantine.glob("*.json")), [])
            finally:
                harness.close()

    def test_server_response_signature_and_request_binding_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.environ["SESSION_BRIDGE_HOME"] = str(root / "security")
            store = hub.HubStore(root / "hub")
            client = connector.HubClient(
                "http://127.0.0.1:8787", store.server_principal
            )
            response = store.signed_response(
                "/v1/status", "a" * 32, {"project_id": "project_test"}
            )
            verified = client._verify_response(
                "/v1/status", response, request_nonce="a" * 32
            )
            self.assertEqual(verified["project_id"], "project_test")
            with self.assertRaisesRegex(connector.ConnectorError, "another request"):
                client._verify_response("/v1/status", response, request_nonce="b" * 32)
            response["result"]["project_id"] = "project_tampered"
            with self.assertRaisesRegex(
                connector.ConnectorError, "signature is invalid"
            ):
                client._verify_response("/v1/status", response, request_nonce="a" * 32)

    def test_authenticated_hub_error_is_signed_before_permanent_classification(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.environ["SESSION_BRIDGE_HOME"] = str(root / "security")
            harness = ConnectorHarness(root)
            try:
                alice = harness.enroll("Alice", root / "alice")
                config = alice.load_config("phoenix")
                with closing(sqlite3.connect(harness.store.database)) as connection:
                    connection.execute(
                        "DELETE FROM memberships WHERE project_id = ? AND principal = ?",
                        (config["project_id"], config["principal"]),
                    )
                    connection.commit()
                with self.assertRaisesRegex(
                    connector.PermanentRejectionError,
                    "not a project member",
                ):
                    alice.client(config).authenticated(
                        "/v1/directory",
                        {"project_id": config["project_id"]},
                        alice.identity_path,
                    )
            finally:
                harness.close()

    def test_mailbox_key_persists_and_private_key_tamper_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.environ["SESSION_BRIDGE_HOME"] = str(root)
            first = connector.load_or_create_mailbox_identity(root)
            second = connector.load_or_create_mailbox_identity(root)
            self.assertEqual(first, second)
            path = root / "mailbox-identity.json"
            value = bridge.load_json(path)
            value["public_key"] = bridge.b64e(b"z" * 32)
            bridge.save_json(path, value)
            with self.assertRaisesRegex(connector.ConnectorError, "do not match"):
                connector.load_or_create_mailbox_identity(root)

    def test_enrollment_retry_is_idempotent_for_same_alias(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.environ["SESSION_BRIDGE_HOME"] = str(root / "security")
            harness = ConnectorHarness(root)
            try:
                enrollment = harness.store.create_enrollment(
                    str(harness.project["project_id"]),
                    "Alice",
                    "member",
                    harness.url,
                )
                endpoint = connector.TeamConnector(root / "alice")
                first = endpoint.enroll("phoenix", str(enrollment["code"]))
                second = endpoint.enroll("phoenix", str(enrollment["code"]))
                self.assertEqual(first, second)
            finally:
                harness.close()

    def test_reviewed_head_publishes_only_once_to_project_agent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.environ["SESSION_BRIDGE_HOME"] = str(root / "shared-security")
            harness = ConnectorHarness(root)
            try:
                alice = harness.enroll("Alice", root / "alice")
                bob = harness.enroll("Bob", root / "bob")
                librarian = harness.enroll(
                    "Project Librarian", root / "librarian", "project-agent"
                )
                alice.trust(
                    "phoenix", str(librarian.load_config("phoenix")["principal"])
                )
                committed_revision(ContextLedger("phoenix", root / "alice"))
                first = alice.publish_head(
                    "phoenix",
                    "phoenix",
                    "project-agents",
                    "12-hour project checkpoint",
                    "internal",
                )
                self.assertEqual(len(first["queued"]), 1)
                self.assertEqual(
                    first["queued"][0]["recipient"],
                    librarian.load_config("phoenix")["principal"],
                )
                second = alice.publish_head(
                    "phoenix",
                    "phoenix",
                    "project-agents",
                    "12-hour project checkpoint",
                    "internal",
                )
                self.assertEqual(second["queued"], [])
                self.assertEqual(len(second["skipped"]), 1)
                alice.flush("phoenix")
                self.assertEqual(
                    librarian.status("phoenix")["remote"]["mailbox"]["pending"],
                    1,
                )
                self.assertNotIn("pending", bob.status("phoenix")["remote"]["mailbox"])
            finally:
                harness.close()

    def test_directory_key_substitution_and_untrusted_publication_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.environ["SESSION_BRIDGE_HOME"] = str(root / "shared-security")
            harness = ConnectorHarness(root)
            try:
                alice = harness.enroll("Alice", root / "alice")
                bob = harness.enroll("Bob", root / "bob")
                bob_principal = str(bob.load_config("phoenix")["principal"])
                directory_result = alice.directory("phoenix")
                bob_entry = next(
                    endpoint
                    for endpoint in directory_result["endpoints"]
                    if endpoint["principal"] == bob_principal
                )
                self.assertEqual(bob_entry["trust"], "untrusted")
                committed_revision(ContextLedger("phoenix", root / "alice"))
                with self.assertRaisesRegex(
                    connector.ConnectorError, "not locally trusted"
                ):
                    alice.publish_head(
                        "phoenix", "phoenix", "team", "checkpoint", "internal"
                    )

                tampered = dict(bob_entry)
                tampered.pop("trust")
                tampered["mailbox_public_key"] = bridge.b64e(b"m" * 32)
                with self.assertRaisesRegex(
                    connector.ConnectorError, "mailbox binding is invalid"
                ):
                    alice._validate_directory_endpoint(
                        tampered, alice.load_config("phoenix")
                    )

                trusted = alice.trust("phoenix", bob_principal)
                self.assertEqual(trusted["principal"], bob_principal)
                self.assertEqual(
                    next(
                        endpoint
                        for endpoint in alice.directory("phoenix")["endpoints"]
                        if endpoint["principal"] == bob_principal
                    )["trust"],
                    "trusted",
                )
                with closing(sqlite3.connect(harness.store.database)) as connection:
                    connection.execute(
                        "UPDATE memberships SET role = 'project-agent' WHERE principal = ?",
                        (bob_principal,),
                    )
                    connection.commit()
                changed = next(
                    endpoint
                    for endpoint in alice.directory("phoenix")["endpoints"]
                    if endpoint["principal"] == bob_principal
                )
                self.assertEqual(changed["trust"], "changed")
                with self.assertRaisesRegex(
                    connector.ConnectorError, "not locally trusted"
                ):
                    alice.publish_head(
                        "phoenix", "phoenix", "team", "checkpoint", "internal"
                    )
                with closing(sqlite3.connect(harness.store.database)) as connection:
                    connection.execute(
                        "UPDATE memberships SET role = 'member' WHERE principal = ?",
                        (bob_principal,),
                    )
                    connection.commit()
                published = alice.publish_head(
                    "phoenix", "phoenix", "team", "checkpoint", "internal"
                )
                self.assertEqual(len(published["queued"]), 1)
                self.assertTrue(alice.untrust("phoenix", bob_principal)["removed"])
            finally:
                harness.close()

    def test_continuous_run_retries_transient_failure_then_recovers(self) -> None:
        active = mock.Mock()
        active.sync.side_effect = [
            connector.TransientConnectorError("temporary outage"),
            {
                "sent": [],
                "project": "phoenix",
                "cursor": 0,
                "quarantined": [],
                "rejected": [],
            },
        ]

        class ImmediateEvent:
            def __init__(self) -> None:
                self.waits: list[int] = []

            def is_set(self) -> bool:
                return False

            def set(self) -> None:
                return None

            def wait(self, seconds: int) -> bool:
                self.waits.append(seconds)
                return False

        stopped = ImmediateEvent()
        args = SimpleNamespace(
            interval_seconds=10,
            retry_min_seconds=2,
            retry_max_seconds=8,
            home=None,
            publish_head=False,
            project="phoenix",
            ledger_project="phoenix",
            audience="project-agents",
            purpose="checkpoint",
            max_sensitivity="internal",
            iterations=2,
        )
        output, errors = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(connector, "TeamConnector", return_value=active),
            mock.patch.object(connector.threading, "Event", return_value=stopped),
            mock.patch.object(connector.signal, "signal"),
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            connector.command_run(args)
        self.assertEqual(stopped.waits, [2])
        failure = json.loads(errors.getvalue())
        self.assertEqual(failure["status"], "retrying")
        self.assertEqual(failure["retry_in_seconds"], 2)
        success = json.loads(output.getvalue())
        self.assertEqual(success["status"], "ok")
        self.assertEqual(active.sync.call_count, 2)

    def test_continuous_run_does_not_hide_permanent_policy_failure(self) -> None:
        active = mock.Mock()
        active.sync.side_effect = connector.ConnectorError("endpoint disabled")
        args = SimpleNamespace(
            interval_seconds=10,
            retry_min_seconds=2,
            retry_max_seconds=8,
            home=None,
            publish_head=False,
            project="phoenix",
            ledger_project="phoenix",
            audience="project-agents",
            purpose="checkpoint",
            max_sensitivity="internal",
            iterations=0,
        )
        with (
            mock.patch.object(connector, "TeamConnector", return_value=active),
            mock.patch.object(connector.signal, "signal"),
            self.assertRaisesRegex(connector.ConnectorError, "endpoint disabled"),
        ):
            connector.command_run(args)


if __name__ == "__main__":
    unittest.main()
