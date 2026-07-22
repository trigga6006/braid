from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
from contextlib import redirect_stdout
import http.client
import io
import json
import multiprocessing
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import network_bridge as bridge  # noqa: E402
from context_model import make_claim  # noqa: E402
from context_security import (  # noqa: E402
    create_identity_assertion,
    identity_principal,
    load_or_create_identity,
)
from context_store import ContextLedger  # noqa: E402


class FakeSession:
    provider = "codex"
    surface = "codex-local"
    title = "LLC planning"
    cwd = "/private/company/llc-project"
    updated = 1_700_000_000.0
    archived = False


def append_event_in_process(arguments: tuple[str, int]) -> int:
    directory_text, index = arguments
    os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = "1"
    directory = Path(directory_text)
    stale_state = {"next_sequence": 1, "event_bytes": 0, "participants": {}}
    return int(
        bridge.append_event(
            directory,
            stale_state,
            {"type": "message", "from": f"worker-{index}", "message": str(index)},
        )["sequence"]
    )


def serve_room_in_process(home: str, directory_text: str, port_file_text: str) -> None:
    os.environ["SESSION_BRIDGE_HOME"] = home
    os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = "1"
    server = bridge.BoundedThreadingHTTPServer(("127.0.0.1", 0), bridge.BridgeHandler)
    server.room_directory = Path(directory_text)
    Path(port_file_text).write_text(str(server.server_address[1]), encoding="ascii")
    server.serve_forever()


class NetworkBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.previous_disable_keychain = os.environ.get(
            "SESSION_BRIDGE_DISABLE_KEYCHAIN"
        )
        os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = "1"

    def tearDown(self) -> None:
        if self.previous_disable_keychain is None:
            os.environ.pop("SESSION_BRIDGE_DISABLE_KEYCHAIN", None)
        else:
            os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = (
                self.previous_disable_keychain
            )

    @staticmethod
    def post_json(
        port: int, path: str, value: dict[str, object]
    ) -> tuple[int, dict[str, object]]:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        body = json.dumps(value).encode("utf-8")
        connection.request(
            "POST", path, body=body, headers={"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
        return response.status, payload

    def test_code_round_trip_and_bom(self) -> None:
        payload = {
            "v": 2,
            "url": "https://example.com",
            "room": "abc123",
            "pair": bridge.b64e(b"p" * 32),
            "host_key": bridge.b64e(b"h" * 32),
            "host_identity": {},
            "transport": "public",
            "fingerprint": "",
            "expires": int(time.time()) + 60,
        }
        self.assertEqual(
            bridge.decode_code("\ufeff" + bridge.encode_code(payload)), payload
        )

    def test_atomic_state_writes_use_unique_temporary_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            errors: list[BaseException] = []
            barrier = threading.Barrier(3)

            def writer(writer_id: int) -> None:
                try:
                    barrier.wait()
                    for sequence in range(50):
                        bridge.save_json(
                            path, {"writer": writer_id, "sequence": sequence}
                        )
                except (
                    BaseException
                ) as error:  # Test harness must retain thread failures.
                    errors.append(error)

            threads = [
                threading.Thread(target=writer, args=(index,)) for index in range(2)
            ]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=10)
            self.assertEqual(errors, [])
            self.assertIn(bridge.load_json(path)["writer"], (0, 1))
            self.assertEqual(list(Path(directory).glob("*.tmp-*")), [])

    def test_expired_code_is_rejected(self) -> None:
        payload = {
            "v": 2,
            "url": "https://example.com",
            "room": "abc123",
            "pair": bridge.b64e(b"p" * 32),
            "host_key": bridge.b64e(b"h" * 32),
            "host_identity": {},
            "transport": "public",
            "fingerprint": "",
            "expires": int(time.time()) - 1,
        }
        with self.assertRaises(SystemExit):
            bridge.decode_code(bridge.encode_code(payload))

    def test_encrypted_channel_round_trip_and_tamper_rejection(self) -> None:
        private_a, public_a = bridge.generate_exchange_keypair()
        private_b, public_b = bridge.generate_exchange_keypair()
        key_a = bridge.derive_channel_key(private_a, public_b, b"s" * 32, "room")
        key_b = bridge.derive_channel_key(private_b, public_a, b"s" * 32, "room")
        aad = b"bound-metadata"
        envelope = bridge.seal_json(key_a, {"context": "test"}, aad)
        self.assertEqual(bridge.open_json(key_b, envelope, aad), {"context": "test"})
        tampered = dict(envelope)
        raw = bytearray(bridge.b64d(tampered["ciphertext"]))
        raw[-1] ^= 1
        tampered["ciphertext"] = bridge.b64e(bytes(raw))
        with self.assertRaises(ValueError):
            bridge.open_json(key_b, tampered, aad)

    def test_secret_protection_round_trip(self) -> None:
        secret = b"participant-channel-key"
        protected = bridge.protect_secret(secret)
        self.assertNotEqual(protected["data"], bridge.b64e(secret)) if protected[
            "scheme"
        ] == "windows-dpapi" else None
        self.assertEqual(bridge.unprotect_secret(protected), secret)

    def test_keychain_backed_secret_encryption_round_trip_and_tamper_rejection(
        self,
    ) -> None:
        key = b"k" * 32
        protected = bridge.seal_keychain_secret(b"local secret", "macos-keychain", key)
        self.assertEqual(
            bridge.open_keychain_secret(protected, "macos-keychain", key),
            b"local secret",
        )
        tampered = dict(protected)
        ciphertext = bytearray(bridge.b64d(tampered["data"]))
        ciphertext[-1] ^= 1
        tampered["data"] = bridge.b64e(bytes(ciphertext))
        with self.assertRaises(SystemExit):
            bridge.open_keychain_secret(tampered, "macos-keychain", key)

    def test_shared_session_redacts_identifiers_and_paths(self) -> None:
        shared = bridge.shareable_session(FakeSession())
        serialized = json.dumps(shared)
        self.assertNotIn("/private/company", serialized)
        self.assertNotIn("session_id", serialized)
        self.assertEqual(shared["project"], "llc-project")

    def test_curated_context_validation_and_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "context.md"
            path.write_text("Decisions:\n- Form the LLC.", encoding="utf-8")
            context = bridge.curated_context(FakeSession(), path)
            bridge.validate_context(context)
            context["characters"] += 1
            with self.assertRaises(ValueError):
                bridge.validate_context(context)

    def test_context_review_reports_purpose_detail_and_missing_sections(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "context.md"
            path.write_text(
                "# Executive Summary\nReady to compare.\n\n# Confirmed Facts\n- One fact."
                "\n\n# Owners and Next Steps\n- Alice verifies it.",
                encoding="utf-8",
            )
            context = bridge.curated_context(
                FakeSession(), path, "Compare LLC advice", "balanced"
            )
            review = bridge.context_review(context)
            self.assertEqual(review["purpose"], "Compare LLC advice")
            self.assertEqual(review["detail"], "balanced")
            self.assertIn("decisions", review["recommended_missing"])
            self.assertNotIn("executive summary", review["recommended_missing"])
            self.assertNotIn("action items", review["recommended_missing"])

    def test_legacy_inline_pairing_code_is_hidden_from_help(self) -> None:
        parser = bridge.build_parser()
        subparsers = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        for name in ("start", "join"):
            help_text = subparsers.choices[name].format_help()
            self.assertNotIn("--code CODE", help_text)
            self.assertIn("--code-file", help_text)

    def test_context_digest_is_verified_before_acceptance(self) -> None:
        context = {
            "format": "session-bridge-context/v1",
            "kind": "curated",
            "purpose": "Verify context integrity",
            "detail": "brief",
            "session": bridge.shareable_session(FakeSession()),
            "created_at": "2026-07-22T00:00:00Z",
            "characters": len("Original context"),
            "sha256": bridge.hashlib.sha256(b"Original context").hexdigest(),
            "content": "Original context",
        }
        bridge.validate_context(context)
        context["content"] = "Modified content"
        context["characters"] = len(context["content"])
        with self.assertRaisesRegex(ValueError, "digest"):
            bridge.validate_context(context)

    def test_append_event_recovers_sequence_after_state_write_loss(self) -> None:
        bridge.crypto_imports()
        with tempfile.TemporaryDirectory() as home:
            directory = Path(home)
            (directory / "events").mkdir()
            state = {"next_sequence": 1}
            first = {
                "sequence": 1,
                "created_at": "2026-07-22T00:00:00Z",
                "type": "message",
            }
            bridge.save_protected_json(bridge.event_path(directory, 1), first)
            recovered = bridge.append_event(
                directory, state, {"type": "message", "message": "after crash"}
            )
            self.assertEqual(recovered["sequence"], 2)
            self.assertEqual(
                bridge.load_protected_json(bridge.event_path(directory, 1)), first
            )

    def test_append_event_refreshes_stale_state_and_preserves_fields(self) -> None:
        bridge.crypto_imports()
        with tempfile.TemporaryDirectory() as home:
            directory = Path(home)
            (directory / "events").mkdir()
            bridge.save_json(
                bridge.state_path(directory),
                {
                    "next_sequence": 5,
                    "event_bytes": 0,
                    "sentinel": "keep",
                    "participants": {"peer": {"receive_counter": 7}},
                },
            )
            stale = {"next_sequence": 1, "event_bytes": 0, "participants": {}}
            result = bridge.append_event(
                directory, stale, {"type": "message", "message": "fresh"}
            )
            persisted = bridge.load_json(bridge.state_path(directory))
            self.assertEqual(result["sequence"], 5)
            self.assertEqual(persisted["next_sequence"], 6)
            self.assertEqual(persisted["sentinel"], "keep")
            self.assertEqual(persisted["participants"]["peer"]["receive_counter"], 7)
            self.assertEqual(stale, persisted)

    def test_large_accepted_event_round_trips_through_at_rest_protection(self) -> None:
        bridge.crypto_imports()
        with tempfile.TemporaryDirectory() as home:
            directory = Path(home)
            (directory / "events").mkdir()
            state = {"next_sequence": 1, "event_bytes": 0, "participants": {}}
            bridge.save_json(bridge.state_path(directory), state)
            payload = "x" * 100_000
            event = bridge.append_event(
                directory,
                state,
                {"type": "context-pack", "bundle": {"payload": payload}},
            )
            loaded = bridge.load_events(directory)
            self.assertEqual(loaded, [event])
            self.assertEqual(loaded[0]["bundle"]["payload"], payload)

    def test_room_event_sequence_is_process_safe_and_poll_is_paginated(self) -> None:
        bridge.crypto_imports()
        with tempfile.TemporaryDirectory() as home:
            directory = Path(home) / "room"
            (directory / "events").mkdir(parents=True)
            bridge.save_json(
                bridge.state_path(directory),
                {"next_sequence": 1, "event_bytes": 0, "participants": {}},
            )
            with ProcessPoolExecutor(max_workers=8) as executor:
                sequences = list(
                    executor.map(
                        append_event_in_process,
                        [(str(directory), index) for index in range(40)],
                    )
                )
            self.assertEqual(sorted(sequences), list(range(1, 41)))
            self.assertEqual(len(list((directory / "events").glob("*.json"))), 40)
            state = bridge.load_json(bridge.state_path(directory))
            self.assertEqual(state["next_sequence"], 41)
            self.assertGreater(state["event_bytes"], 0)
            first_page = bridge.load_events(directory)
            self.assertEqual(len(first_page), bridge.MAX_POLL_EVENTS)
            second_page = bridge.load_events(
                directory, after=int(first_page[-1]["sequence"])
            )
            self.assertEqual(len(second_page), 8)

    def test_credential_like_context_requires_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "context.md"
            path.write_text(
                "Do not share -----BEGIN PRIVATE KEY----- material", encoding="utf-8"
            )
            with self.assertRaises(SystemExit):
                bridge.build_context(FakeSession(), str(path), False, 1000, False)
            with self.assertRaises(SystemExit):
                bridge.build_context(FakeSession(), str(path), False, 1000, True)

    def test_pairing_context_uses_full_ledger_credential_scanner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "context.md"
            for secret in (
                "password=correcthorsebatterystaple",
                "postgresql://alice:correcthorsebatterystaple@db.example/app",
                "xox" + "b-1234567890-abcdefghijklmnop",
            ):
                path.write_text(secret, encoding="utf-8")
                with self.subTest(secret=secret[:12]):
                    with self.assertRaises(SystemExit):
                        bridge.build_context(
                            FakeSession(), str(path), False, 1000, False
                        )

    def test_private_address_policy(self) -> None:
        self.assertTrue(bridge.private_host("127.0.0.1"))
        self.assertTrue(bridge.private_host("192.168.1.7"))
        self.assertTrue(bridge.private_host("100.64.0.1"))
        self.assertFalse(bridge.private_host("8.8.8.8"))

    def test_message_limit(self) -> None:
        args = argparse.Namespace(
            message="x" * (bridge.MAX_MESSAGE_CHARS + 1), message_file=None, stdin=False
        )
        with self.assertRaises(SystemExit):
            bridge.read_message(args)

    def test_join_setup_never_installs_cloudflared(self) -> None:
        args = argparse.Namespace(role="join", yes=True, update=False)
        with (
            mock.patch.object(
                bridge, "ensure_cryptography", return_value=bridge.REQUIRED_CRYPTOGRAPHY
            ),
            mock.patch.object(bridge, "setup_cloudflared") as setup_cloudflared,
            redirect_stdout(io.StringIO()) as output,
        ):
            bridge.command_setup(args)
        setup_cloudflared.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["role"], "join")

    def test_local_setup_has_no_dependency_work(self) -> None:
        args = argparse.Namespace(role="local", yes=False, update=False)
        with (
            mock.patch.object(bridge, "ensure_cryptography") as ensure_crypto,
            redirect_stdout(io.StringIO()),
        ):
            bridge.command_setup(args)
        ensure_crypto.assert_not_called()

    def test_start_dispatches_to_selected_role(self) -> None:
        host_args = argparse.Namespace(role="host")
        join_args = argparse.Namespace(
            role="join", code="code", code_file=None, code_stdin=False
        )
        with (
            mock.patch.object(bridge, "command_host") as host,
            mock.patch.object(bridge, "command_join") as join,
        ):
            bridge.command_start(host_args)
            bridge.command_start(join_args)
        host.assert_called_once_with(host_args)
        join.assert_called_once_with(join_args)

    def test_cloudflared_download_is_release_and_digest_pinned(self) -> None:
        asset, url, digest = bridge.cloudflared_download_spec()
        self.assertIn(asset, bridge.CLOUDFLARED_ASSETS)
        self.assertIn(f"/download/{bridge.CLOUDFLARED_RELEASE}/", url)
        self.assertEqual(digest, bridge.CLOUDFLARED_ASSETS[asset])
        self.assertEqual(len(digest), 64)

    def test_private_cloudflared_is_reverified_before_reuse(self) -> None:
        previous_home = os.environ.get("SESSION_BRIDGE_HOME")
        with tempfile.TemporaryDirectory() as home:
            os.environ["SESSION_BRIDGE_HOME"] = home
            binary = Path(home) / "bin" / "cloudflared"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"verified helper")
            digest = bridge.sha256_file(binary)
            try:
                with mock.patch.object(
                    bridge,
                    "cloudflared_download_spec",
                    return_value=(
                        "cloudflared-linux-amd64",
                        "https://example.invalid/helper",
                        digest,
                    ),
                ):
                    self.assertTrue(bridge.verified_private_cloudflared(binary))
                    binary.write_bytes(b"modified helper")
                    self.assertFalse(bridge.verified_private_cloudflared(binary))
            finally:
                if previous_home is None:
                    os.environ.pop("SESSION_BRIDGE_HOME", None)
                else:
                    os.environ["SESSION_BRIDGE_HOME"] = previous_home

    def test_unverified_path_cloudflared_is_never_executed_implicitly(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            previous = os.environ.get("SESSION_BRIDGE_HOME")
            configured = os.environ.pop("SESSION_BRIDGE_CLOUDFLARED", None)
            os.environ["SESSION_BRIDGE_HOME"] = home
            try:
                with mock.patch.object(
                    bridge.shutil,
                    "which",
                    return_value=str(Path(home) / "attacker-cloudflared"),
                ) as which:
                    self.assertEqual(bridge.find_cloudflared(), "")
                which.assert_not_called()
            finally:
                if previous is None:
                    os.environ.pop("SESSION_BRIDGE_HOME", None)
                else:
                    os.environ["SESSION_BRIDGE_HOME"] = previous
                if configured is not None:
                    os.environ["SESSION_BRIDGE_CLOUDFLARED"] = configured

    def test_tunnel_process_stops_when_startup_state_save_fails(self) -> None:
        class FakeProcess:
            pid = 12345

            def __init__(self) -> None:
                self.stopped = False

            def poll(self) -> int | None:
                return 0 if self.stopped else None

            def terminate(self) -> None:
                self.stopped = True

            def wait(self, timeout: float | None = None) -> int:
                return 0

            def kill(self) -> None:
                self.stopped = True

        with tempfile.TemporaryDirectory() as home:
            directory = Path(home) / "room"
            directory.mkdir()
            state = {"room_id": "room", "port": 1234, "public_url": ""}
            bridge.save_json(bridge.state_path(directory), state)
            (directory / "tunnel.log").write_text(
                "Tunnel ready at https://safe-test.trycloudflare.com\n",
                encoding="utf-8",
            )
            process = FakeProcess()
            with (
                mock.patch.object(
                    bridge, "find_cloudflared", return_value="cloudflared"
                ),
                mock.patch.object(bridge.subprocess, "Popen", return_value=process),
                mock.patch.object(
                    bridge,
                    "save_json",
                    side_effect=PermissionError("simulated state race"),
                ),
            ):
                with self.assertRaises(PermissionError):
                    bridge.start_tunnel(state, directory)
            self.assertTrue(process.stopped)

    def test_watch_host_remembers_cursor_and_say_routes_to_peer(self) -> None:
        bridge.crypto_imports()
        previous_home = os.environ.get("SESSION_BRIDGE_HOME")
        with tempfile.TemporaryDirectory() as home:
            os.environ["SESSION_BRIDGE_HOME"] = home
            room_id = "collaboration-room"
            directory = bridge.room_dir(room_id)
            (directory / "events").mkdir(parents=True)
            state = {
                "room_id": room_id,
                "closed": False,
                "expires": int(time.time()) + 600,
                "participants": {"peer-test": {"status": "approved"}},
                "next_sequence": 1,
            }
            bridge.save_json(bridge.state_path(directory), state)
            bridge.append_event(
                directory,
                state,
                {
                    "type": "message",
                    "from": "peer-test",
                    "to": "host",
                    "message": "First finding",
                },
            )
            try:
                with redirect_stdout(io.StringIO()) as first_output:
                    bridge.command_watch(
                        argparse.Namespace(
                            id=room_id,
                            wait=0,
                            timeout=1,
                            output=None,
                            json=True,
                        )
                    )
                first = json.loads(first_output.getvalue())
                self.assertEqual(
                    [event["message"] for event in first["events"]], ["First finding"]
                )
                self.assertEqual(first["cursor"], 1)

                with redirect_stdout(io.StringIO()) as empty_output:
                    bridge.command_watch(
                        argparse.Namespace(
                            id=room_id,
                            wait=0,
                            timeout=1,
                            output=None,
                            json=True,
                        )
                    )
                self.assertEqual(json.loads(empty_output.getvalue())["events"], [])

                with redirect_stdout(io.StringIO()):
                    bridge.command_say(
                        argparse.Namespace(
                            id=room_id,
                            timeout=1,
                            json=True,
                            message="Host synthesis",
                            message_file=None,
                            stdin=False,
                        )
                    )
                events = bridge.load_events(directory)
                self.assertEqual(events[-1]["to"], "peer-test")
                self.assertEqual(events[-1]["message"], "Host synthesis")

                current = bridge.load_json(bridge.state_path(directory))
                bridge.append_event(
                    directory,
                    current,
                    {
                        "type": "message",
                        "from": "peer-test",
                        "to": "host",
                        "message": "Second finding",
                    },
                )
                with redirect_stdout(io.StringIO()) as second_output:
                    bridge.command_watch(
                        argparse.Namespace(
                            id=room_id,
                            wait=0,
                            timeout=1,
                            output=None,
                            json=True,
                        )
                    )
                second = json.loads(second_output.getvalue())
                self.assertEqual(
                    [event["message"] for event in second["events"]], ["Second finding"]
                )
                self.assertEqual(second["cursor"], 3)
            finally:
                if previous_home is None:
                    os.environ.pop("SESSION_BRIDGE_HOME", None)
                else:
                    os.environ["SESSION_BRIDGE_HOME"] = previous_home

    def test_watch_and_say_route_through_join_connection(self) -> None:
        previous_home = os.environ.get("SESSION_BRIDGE_HOME")
        with tempfile.TemporaryDirectory() as home:
            os.environ["SESSION_BRIDGE_HOME"] = home
            path = Path(home) / "connections" / "join-connection.json"
            connection = {
                "connection_id": "join-connection",
                "room_id": "room",
                "peer_id": "peer-test",
                "status": "approved",
                "cursor": 0,
            }
            path.parent.mkdir(parents=True)
            bridge.save_json(path, connection)
            try:
                with (
                    mock.patch.object(
                        bridge, "load_connection", return_value=(path, connection)
                    ),
                    mock.patch.object(
                        bridge, "channel_request", return_value={"accepted": True}
                    ) as request,
                    redirect_stdout(io.StringIO()),
                ):
                    bridge.command_say(
                        argparse.Namespace(
                            id="join-connection",
                            timeout=1,
                            json=True,
                            message="Joiner finding",
                            message_file=None,
                            stdin=False,
                        )
                    )
                self.assertEqual(
                    request.call_args.args[1:3],
                    ("message", {"message": "Joiner finding"}),
                )

                reply = {
                    "events": [
                        {
                            "sequence": 2,
                            "type": "message",
                            "from": "host",
                            "to": "peer-test",
                            "message": "Host answer",
                        }
                    ],
                    "cursor": 2,
                    "status": "approved",
                }
                with (
                    mock.patch.object(
                        bridge, "load_connection", return_value=(path, connection)
                    ),
                    mock.patch.object(bridge, "channel_request", return_value=reply),
                    redirect_stdout(io.StringIO()) as output,
                ):
                    bridge.command_watch(
                        argparse.Namespace(
                            id="join-connection",
                            wait=0,
                            timeout=1,
                            output=None,
                            json=True,
                        )
                    )
                watched = json.loads(output.getvalue())
                self.assertEqual(watched["kind"], "join")
                self.assertEqual(watched["events"][0]["message"], "Host answer")
                self.assertEqual(watched["cursor"], 2)
            finally:
                if previous_home is None:
                    os.environ.pop("SESSION_BRIDGE_HOME", None)
                else:
                    os.environ["SESSION_BRIDGE_HOME"] = previous_home

    def test_channel_request_recovers_an_accepted_request_after_response_loss(
        self,
    ) -> None:
        bridge.crypto_imports()
        previous_home = os.environ.get("SESSION_BRIDGE_HOME")
        previous_disable_keychain = os.environ.get("SESSION_BRIDGE_DISABLE_KEYCHAIN")
        with tempfile.TemporaryDirectory() as home:
            os.environ["SESSION_BRIDGE_HOME"] = home
            os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = "1"
            key = b"k" * 32
            path = Path(home) / "connections" / "recover.json"
            path.parent.mkdir()
            connection = {
                "connection_id": "recover",
                "room_id": "room",
                "peer_id": "peer",
                "origin": "https://example.invalid",
                "fingerprint": "",
                "channel_key": bridge.protect_secret(key),
                "send_counter": 0,
                "recv_counter": 0,
            }
            bridge.save_json(path, connection)
            try:
                with mock.patch.object(
                    bridge,
                    "request_json",
                    side_effect=SystemExit(
                        "Could not reach the Session Bridge host: lost response"
                    ),
                ):
                    with self.assertRaises(SystemExit):
                        bridge.channel_request(
                            connection,
                            "message",
                            {"message": "once"},
                            1,
                            persist_path=path,
                        )
                persisted = bridge.load_json(path)
                self.assertEqual(persisted["send_counter"], 1)
                self.assertEqual(persisted["pending_request"]["endpoint"], "message")
                response = {
                    "counter": 1,
                    "envelope": bridge.seal_json(
                        key,
                        {"accepted": True},
                        bridge.channel_aad(
                            "room", "peer", "host-to-peer", "message", 1
                        ),
                    ),
                }
                with mock.patch.object(
                    bridge, "request_json", return_value=response
                ) as request:
                    recovered = bridge.channel_request(
                        persisted, "message", {"message": "once"}, 1, persist_path=path
                    )
                self.assertEqual(recovered, {"accepted": True})
                request.assert_called_once()
                final = bridge.load_json(path)
                self.assertNotIn("pending_request", final)
                self.assertEqual(final["recv_counter"], 1)
            finally:
                if previous_home is None:
                    os.environ.pop("SESSION_BRIDGE_HOME", None)
                else:
                    os.environ["SESSION_BRIDGE_HOME"] = previous_home
                if previous_disable_keychain is None:
                    os.environ.pop("SESSION_BRIDGE_DISABLE_KEYCHAIN", None)
                else:
                    os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = (
                        previous_disable_keychain
                    )

    def test_channel_request_discards_terminal_rejection_and_advances(self) -> None:
        bridge.crypto_imports()
        previous_home = os.environ.get("SESSION_BRIDGE_HOME")
        previous_disable_keychain = os.environ.get("SESSION_BRIDGE_DISABLE_KEYCHAIN")
        with tempfile.TemporaryDirectory() as home:
            os.environ["SESSION_BRIDGE_HOME"] = home
            os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = "1"
            key = b"r" * 32
            path = Path(home) / "connections" / "reject.json"
            path.parent.mkdir()
            connection = {
                "connection_id": "reject",
                "room_id": "room",
                "peer_id": "peer",
                "origin": "https://example.invalid",
                "fingerprint": "",
                "channel_key": bridge.protect_secret(key),
                "send_counter": 0,
                "recv_counter": 0,
            }
            bridge.save_json(path, connection)
            try:
                with mock.patch.object(
                    bridge,
                    "request_json",
                    side_effect=bridge.HostRejected(409, "rejected"),
                ):
                    with self.assertRaises(bridge.HostRejected):
                        bridge.channel_request(
                            connection,
                            "message",
                            {"message": "invalid"},
                            1,
                            persist_path=path,
                        )
                rejected = bridge.load_json(path)
                self.assertNotIn("pending_request", rejected)
                self.assertEqual(rejected["send_counter"], 1)

                response = {
                    "counter": 1,
                    "envelope": bridge.seal_json(
                        key,
                        {"accepted": True},
                        bridge.channel_aad(
                            "room", "peer", "host-to-peer", "message", 1
                        ),
                    ),
                }
                with mock.patch.object(
                    bridge, "request_json", return_value=response
                ) as request:
                    result = bridge.channel_request(
                        rejected,
                        "message",
                        {"message": "valid"},
                        1,
                        persist_path=path,
                    )
                self.assertEqual(result, {"accepted": True})
                self.assertEqual(request.call_args.args[4]["counter"], 2)
                self.assertNotIn("pending_request", bridge.load_json(path))
            finally:
                if previous_home is None:
                    os.environ.pop("SESSION_BRIDGE_HOME", None)
                else:
                    os.environ["SESSION_BRIDGE_HOME"] = previous_home
                if previous_disable_keychain is None:
                    os.environ.pop("SESSION_BRIDGE_DISABLE_KEYCHAIN", None)
                else:
                    os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = (
                        previous_disable_keychain
                    )

    def test_complete_pair_approve_exchange_replay_and_close_flow(self) -> None:
        # Load the verified dependency before isolating bridge state in a temporary home.
        bridge.crypto_imports()
        previous_home = os.environ.get("SESSION_BRIDGE_HOME")
        previous_disable_keychain = os.environ.get("SESSION_BRIDGE_DISABLE_KEYCHAIN")
        with tempfile.TemporaryDirectory() as home:
            os.environ["SESSION_BRIDGE_HOME"] = home
            os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = "1"
            room_id = "integration-room"
            directory = bridge.room_dir(room_id)
            directory.mkdir()
            for child in ("events", "pending"):
                (directory / child).mkdir()
            host_private, host_public = bridge.generate_exchange_keypair()
            pair_secret = b"p" * 32
            host_context = {
                "format": "session-bridge-context/v1",
                "kind": "curated",
                "purpose": "Compare advice",
                "detail": "brief",
                "session": bridge.shareable_session(FakeSession()),
                "created_at": "2026-07-14T10:00:00Z",
                "characters": 12,
                "sha256": bridge.hashlib.sha256(b"Host context").hexdigest(),
                "content": "Host context",
            }
            peer_context = {
                **host_context,
                "characters": 12,
                "sha256": bridge.hashlib.sha256(b"Peer context").hexdigest(),
                "content": "Peer context",
            }
            now = int(time.time())
            host_recipient_identity = load_or_create_identity(
                Path(home) / "recipient-identity.json"
            )
            peer_recipient_identity = load_or_create_identity(
                Path(home) / "peer-recipient-identity.json"
            )
            host_principal = identity_principal(host_recipient_identity)
            state = {
                "version": 2,
                "room_id": room_id,
                "created_at": "2026-07-14T10:00:00Z",
                "transport": "public",
                "bind": "127.0.0.1",
                "port": 0,
                "origin": "",
                "public_url": "",
                "fingerprint": "",
                "pair_secret": bridge.protect_secret(pair_secret),
                "pair_used": False,
                "pair_expires": now + 60,
                "expires": now + 600,
                "closed": False,
                "purge_on_close": True,
                "host_private": bridge.protect_secret(host_private),
                "host_public": bridge.b64e(host_public),
                "host_session": bridge.shareable_session(FakeSession()),
                "host_context": bridge.context_metadata(host_context),
                "principal": host_principal,
                "participants": {},
                "next_sequence": 1,
            }
            bridge.save_protected_json(
                directory / "host-context.json", {"context": host_context}
            )
            bridge.save_json(bridge.state_path(directory), state)
            port_file = Path(home) / "server-port.txt"
            process = multiprocessing.get_context("spawn").Process(
                target=serve_room_in_process,
                args=(home, str(directory), str(port_file)),
                daemon=True,
            )
            process.start()
            try:
                deadline = time.monotonic() + 30
                port = 0
                while time.monotonic() < deadline:
                    if process.exitcode is not None:
                        self.fail(
                            "Bridge server process exited during startup with "
                            f"code {process.exitcode}."
                        )
                    if not port and port_file.exists():
                        port = int(port_file.read_text(encoding="ascii"))
                    if not port:
                        time.sleep(0.02)
                        continue
                    connection = http.client.HTTPConnection(
                        "127.0.0.1", port, timeout=1
                    )
                    try:
                        connection.request("GET", "/v2/ready")
                        response = connection.getresponse()
                        response.read()
                        if response.status == 200:
                            break
                    except OSError:
                        time.sleep(0.02)
                    finally:
                        connection.close()
                else:
                    process.terminate()
                    process.join(timeout=5)
                    self.fail(
                        "Bridge server process did not become ready; "
                        f"port_handoff={port_file.exists()}, port={port}"
                    )
                client_private, client_public = bridge.generate_exchange_keypair()
                key = bridge.derive_channel_key(
                    client_private, host_public, pair_secret, room_id
                )
                client_public_text = bridge.b64e(client_public)
                join_request = {
                    "session": bridge.shareable_session(FakeSession()),
                    "context": peer_context,
                    "message": "Compare these.",
                    "identity": create_identity_assertion(
                        peer_recipient_identity,
                        {
                            "role": "join",
                            "room_id": room_id,
                            "exchange_key": client_public_text,
                            "host_principal": host_principal,
                            "expires": state["pair_expires"],
                        },
                    ),
                }
                status, joined = self.post_json(
                    port,
                    "/v2/join",
                    {
                        "client_key": client_public_text,
                        "envelope": bridge.seal_json(
                            key,
                            join_request,
                            bridge.join_aad(room_id, client_public_text),
                        ),
                    },
                )
                self.assertEqual(status, 200, joined)
                peer_id = str(joined["peer_id"])
                details = bridge.open_json(
                    key, joined["envelope"], bridge.join_response_aad(room_id, peer_id)
                )
                self.assertEqual(details["status"], "pending")
                with redirect_stdout(io.StringIO()) as status_output:
                    bridge.command_status(argparse.Namespace(id=room_id, json=True))
                self.assertEqual(
                    json.loads(status_output.getvalue())["next_action"],
                    "compare_safety_code_and_approve",
                )

                poll_one = {
                    "peer_id": peer_id,
                    "counter": 1,
                    "envelope": bridge.seal_json(
                        key,
                        {"after": 0},
                        bridge.channel_aad(room_id, peer_id, "peer-to-host", "poll", 1),
                    ),
                }
                status, pending_poll = self.post_json(port, "/v2/poll", poll_one)
                self.assertEqual(status, 200)
                pending_payload = bridge.open_json(
                    key,
                    pending_poll["envelope"],
                    bridge.channel_aad(
                        room_id,
                        peer_id,
                        "host-to-peer",
                        "poll",
                        int(pending_poll["counter"]),
                    ),
                )
                self.assertEqual(pending_payload["events"], [])

                with redirect_stdout(io.StringIO()):
                    bridge.command_approve(
                        argparse.Namespace(
                            room=room_id,
                            peer=peer_id,
                            safety_code=str(details["safety_code"]),
                        )
                    )
                poll_two = {
                    "peer_id": peer_id,
                    "counter": 2,
                    "envelope": bridge.seal_json(
                        key,
                        {"after": 0},
                        bridge.channel_aad(room_id, peer_id, "peer-to-host", "poll", 2),
                    ),
                }
                status, approved_poll = self.post_json(port, "/v2/poll", poll_two)
                self.assertEqual(status, 200)
                approved_payload = bridge.open_json(
                    key,
                    approved_poll["envelope"],
                    bridge.channel_aad(
                        room_id,
                        peer_id,
                        "host-to-peer",
                        "poll",
                        int(approved_poll["counter"]),
                    ),
                )
                self.assertEqual(approved_payload["status"], "approved")
                self.assertEqual(
                    approved_payload["events"][0]["context"]["content"], "Host context"
                )
                host_events = [
                    event
                    for event in bridge.load_events(directory)
                    if event.get("to") == "host"
                ]
                self.assertEqual(host_events[0]["context"]["content"], "Peer context")

                retry_status, retried_poll = self.post_json(port, "/v2/poll", poll_two)
                self.assertEqual(retry_status, 200)
                self.assertEqual(retried_poll, approved_poll)
                altered_same_counter = {
                    "peer_id": peer_id,
                    "counter": 2,
                    "envelope": bridge.seal_json(
                        key,
                        {"after": 1},
                        bridge.channel_aad(room_id, peer_id, "peer-to-host", "poll", 2),
                    ),
                }
                replay_status, _ = self.post_json(
                    port, "/v2/poll", altered_same_counter
                )
                self.assertEqual(replay_status, 409)
                ledger = ContextLedger("network-e2e", Path(home) / "ledger-data")
                staged = ledger.stage(
                    [
                        make_claim(
                            "claim-network",
                            "decision",
                            "Use signed typed context events.",
                            "typed-events",
                            [
                                {
                                    "type": "test_result",
                                    "uri": "test:network-e2e",
                                    "digest": "sha256:" + "a" * 64,
                                    "observed_at": "2026-07-22T00:00:00Z",
                                }
                            ],
                            observed_at="2026-07-22T00:00:00Z",
                        )
                    ],
                )
                review = ledger.review_staged(staged["stage_id"])
                ledger.approve_staged(staged["stage_id"], review["review_digest"])
                committed = ledger.commit("integration-test")
                bundle_path = Path(home) / "network-bundle.json"
                ledger.export(
                    committed["id"],
                    bundle_path,
                    host_principal,
                )
                signed_bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
                typed_request = {
                    "peer_id": peer_id,
                    "counter": 3,
                    "envelope": bridge.seal_json(
                        key,
                        {"bundle": signed_bundle},
                        bridge.channel_aad(
                            room_id, peer_id, "peer-to-host", "event", 3
                        ),
                    ),
                }
                event_status, event_response = self.post_json(
                    port, "/v2/event", typed_request
                )
                self.assertEqual(event_status, 200)
                accepted = bridge.open_json(
                    key,
                    event_response["envelope"],
                    bridge.channel_aad(
                        room_id,
                        peer_id,
                        "host-to-peer",
                        "event",
                        int(event_response["counter"]),
                    ),
                )
                self.assertTrue(accepted["accepted"])
                host_events = [
                    event
                    for event in bridge.load_events(directory)
                    if event.get("to") == "host"
                ]
                self.assertEqual(host_events[-1]["type"], "context-pack")
                self.assertEqual(
                    host_events[-1]["metadata"]["recipient"],
                    host_principal,
                )
                self.assertEqual(host_events[-1]["metadata"]["claims"], 1)
                with redirect_stdout(io.StringIO()):
                    bridge.command_finish(argparse.Namespace(id=room_id))
                self.assertFalse(directory.exists())
            finally:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
                    if process.is_alive():
                        process.kill()
                        process.join(timeout=5)
                bridge.safe_remove_room(directory)
                if previous_home is None:
                    os.environ.pop("SESSION_BRIDGE_HOME", None)
                else:
                    os.environ["SESSION_BRIDGE_HOME"] = previous_home
                if previous_disable_keychain is None:
                    os.environ.pop("SESSION_BRIDGE_DISABLE_KEYCHAIN", None)
                else:
                    os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = (
                        previous_disable_keychain
                    )


if __name__ == "__main__":
    unittest.main()
