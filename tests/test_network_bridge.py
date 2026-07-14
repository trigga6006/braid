from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import http.client
import io
import json
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


class FakeSession:
    provider = "codex"
    surface = "codex-local"
    title = "LLC planning"
    cwd = "/private/company/llc-project"
    updated = 1_700_000_000.0
    archived = False


class NetworkBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.previous_disable_keychain = os.environ.get("SESSION_BRIDGE_DISABLE_KEYCHAIN")
        os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = "1"

    def tearDown(self) -> None:
        if self.previous_disable_keychain is None:
            os.environ.pop("SESSION_BRIDGE_DISABLE_KEYCHAIN", None)
        else:
            os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = self.previous_disable_keychain

    @staticmethod
    def post_json(port: int, path: str, value: dict[str, object]) -> tuple[int, dict[str, object]]:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        body = json.dumps(value).encode("utf-8")
        connection.request("POST", path, body=body, headers={"Content-Type": "application/json"})
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
            "transport": "public",
            "fingerprint": "",
            "expires": int(time.time()) + 60,
        }
        self.assertEqual(bridge.decode_code("\ufeff" + bridge.encode_code(payload)), payload)

    def test_atomic_state_writes_use_unique_temporary_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            errors: list[BaseException] = []
            barrier = threading.Barrier(3)

            def writer(writer_id: int) -> None:
                try:
                    barrier.wait()
                    for sequence in range(50):
                        bridge.save_json(path, {"writer": writer_id, "sequence": sequence})
                except BaseException as error:  # Test harness must retain thread failures.
                    errors.append(error)

            threads = [threading.Thread(target=writer, args=(index,)) for index in range(2)]
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
        self.assertNotEqual(protected["data"], bridge.b64e(secret)) if protected["scheme"] == "windows-dpapi" else None
        self.assertEqual(bridge.unprotect_secret(protected), secret)

    def test_keychain_backed_secret_encryption_round_trip_and_tamper_rejection(self) -> None:
        key = b"k" * 32
        protected = bridge.seal_keychain_secret(b"local secret", "macos-keychain", key)
        self.assertEqual(bridge.open_keychain_secret(protected, "macos-keychain", key), b"local secret")
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
            path.write_text("# Executive Summary\nReady to compare.\n\n# Confirmed Facts\n- One fact.", encoding="utf-8")
            context = bridge.curated_context(FakeSession(), path, "Compare LLC advice", "balanced")
            review = bridge.context_review(context)
            self.assertEqual(review["purpose"], "Compare LLC advice")
            self.assertEqual(review["detail"], "balanced")
            self.assertIn("decisions", review["recommended_missing"])
            self.assertNotIn("executive summary", review["recommended_missing"])

    def test_credential_like_context_requires_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "context.md"
            path.write_text("Do not share -----BEGIN PRIVATE KEY----- material", encoding="utf-8")
            with self.assertRaises(SystemExit):
                bridge.build_context(FakeSession(), str(path), False, 1000, False)
            context = bridge.build_context(FakeSession(), str(path), False, 1000, True)
            self.assertEqual(context["kind"], "curated")

    def test_private_address_policy(self) -> None:
        self.assertTrue(bridge.private_host("127.0.0.1"))
        self.assertTrue(bridge.private_host("192.168.1.7"))
        self.assertTrue(bridge.private_host("100.64.0.1"))
        self.assertFalse(bridge.private_host("8.8.8.8"))

    def test_message_limit(self) -> None:
        args = argparse.Namespace(message="x" * (bridge.MAX_MESSAGE_CHARS + 1), message_file=None, stdin=False)
        with self.assertRaises(SystemExit):
            bridge.read_message(args)

    def test_join_setup_never_installs_cloudflared(self) -> None:
        args = argparse.Namespace(role="join", yes=True, update=False)
        with (
            mock.patch.object(bridge, "ensure_cryptography", return_value=bridge.REQUIRED_CRYPTOGRAPHY),
            mock.patch.object(bridge, "setup_cloudflared") as setup_cloudflared,
            redirect_stdout(io.StringIO()) as output,
        ):
            bridge.command_setup(args)
        setup_cloudflared.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["role"], "join")

    def test_local_setup_has_no_dependency_work(self) -> None:
        args = argparse.Namespace(role="local", yes=False, update=False)
        with mock.patch.object(bridge, "ensure_cryptography") as ensure_crypto, redirect_stdout(io.StringIO()):
            bridge.command_setup(args)
        ensure_crypto.assert_not_called()

    def test_start_dispatches_to_selected_role(self) -> None:
        host_args = argparse.Namespace(role="host")
        join_args = argparse.Namespace(role="join", code="code", code_file=None, code_stdin=False)
        with mock.patch.object(bridge, "command_host") as host, mock.patch.object(bridge, "command_join") as join:
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
                    bridge, "cloudflared_download_spec",
                    return_value=("cloudflared-linux-amd64", "https://example.invalid/helper", digest),
                ):
                    self.assertTrue(bridge.verified_private_cloudflared(binary))
                    binary.write_bytes(b"modified helper")
                    self.assertFalse(bridge.verified_private_cloudflared(binary))
            finally:
                if previous_home is None:
                    os.environ.pop("SESSION_BRIDGE_HOME", None)
                else:
                    os.environ["SESSION_BRIDGE_HOME"] = previous_home

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
                "Tunnel ready at https://safe-test.trycloudflare.com\n", encoding="utf-8"
            )
            process = FakeProcess()
            with (
                mock.patch.object(bridge, "find_cloudflared", return_value="cloudflared"),
                mock.patch.object(bridge.subprocess, "Popen", return_value=process),
                mock.patch.object(bridge, "save_json", side_effect=PermissionError("simulated state race")),
            ):
                with self.assertRaises(PermissionError):
                    bridge.start_tunnel(state, directory)
            self.assertTrue(process.stopped)

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
                "format": "session-bridge-context/v1", "kind": "curated",
                "purpose": "Compare advice", "detail": "brief",
                "session": bridge.shareable_session(FakeSession()), "created_at": "2026-07-14T10:00:00Z",
                "characters": 12, "sha256": "h" * 64, "content": "Host context",
            }
            peer_context = {
                **host_context, "characters": 12, "sha256": "j" * 64, "content": "Peer context",
            }
            now = int(time.time())
            state = {
                "version": 2, "room_id": room_id, "created_at": "2026-07-14T10:00:00Z",
                "transport": "public", "bind": "127.0.0.1", "port": 0, "origin": "",
                "public_url": "", "fingerprint": "", "pair_secret": bridge.protect_secret(pair_secret),
                "pair_used": False, "pair_expires": now + 60, "expires": now + 600,
                "closed": False, "purge_on_close": True, "host_private": bridge.protect_secret(host_private),
                "host_public": bridge.b64e(host_public), "host_session": bridge.shareable_session(FakeSession()),
                "host_context": bridge.context_metadata(host_context), "participants": {}, "next_sequence": 1,
            }
            bridge.save_protected_json(directory / "host-context.json", {"context": host_context})
            bridge.save_json(bridge.state_path(directory), state)
            server = bridge.BoundedThreadingHTTPServer(("127.0.0.1", 0), bridge.BridgeHandler)
            server.room_directory = directory
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = int(server.server_address[1])
                client_private, client_public = bridge.generate_exchange_keypair()
                key = bridge.derive_channel_key(client_private, host_public, pair_secret, room_id)
                client_public_text = bridge.b64e(client_public)
                join_request = {
                    "session": bridge.shareable_session(FakeSession()), "context": peer_context, "message": "Compare these.",
                }
                status, joined = self.post_json(port, "/v2/join", {
                    "client_key": client_public_text,
                    "envelope": bridge.seal_json(key, join_request, bridge.join_aad(room_id, client_public_text)),
                })
                self.assertEqual(status, 200)
                peer_id = str(joined["peer_id"])
                details = bridge.open_json(key, joined["envelope"], bridge.join_response_aad(room_id, peer_id))
                self.assertEqual(details["status"], "pending")
                with redirect_stdout(io.StringIO()) as status_output:
                    bridge.command_status(argparse.Namespace(id=room_id, json=True))
                self.assertEqual(json.loads(status_output.getvalue())["next_action"], "compare_safety_code_and_approve")

                poll_one = {
                    "peer_id": peer_id, "counter": 1,
                    "envelope": bridge.seal_json(
                        key, {"after": 0}, bridge.channel_aad(room_id, peer_id, "peer-to-host", "poll", 1),
                    ),
                }
                status, pending_poll = self.post_json(port, "/v2/poll", poll_one)
                self.assertEqual(status, 200)
                pending_payload = bridge.open_json(
                    key, pending_poll["envelope"],
                    bridge.channel_aad(room_id, peer_id, "host-to-peer", "poll", int(pending_poll["counter"])),
                )
                self.assertEqual(pending_payload["events"], [])

                with redirect_stdout(io.StringIO()):
                    bridge.command_approve(argparse.Namespace(
                        room=room_id, peer=peer_id, safety_code=str(details["safety_code"]),
                    ))
                poll_two = {
                    "peer_id": peer_id, "counter": 2,
                    "envelope": bridge.seal_json(
                        key, {"after": 0}, bridge.channel_aad(room_id, peer_id, "peer-to-host", "poll", 2),
                    ),
                }
                status, approved_poll = self.post_json(port, "/v2/poll", poll_two)
                self.assertEqual(status, 200)
                approved_payload = bridge.open_json(
                    key, approved_poll["envelope"],
                    bridge.channel_aad(room_id, peer_id, "host-to-peer", "poll", int(approved_poll["counter"])),
                )
                self.assertEqual(approved_payload["status"], "approved")
                self.assertEqual(approved_payload["events"][0]["context"]["content"], "Host context")
                host_events = [event for event in bridge.load_events(directory) if event.get("to") == "host"]
                self.assertEqual(host_events[0]["context"]["content"], "Peer context")

                replay_status, _ = self.post_json(port, "/v2/poll", poll_two)
                self.assertEqual(replay_status, 409)
                with redirect_stdout(io.StringIO()):
                    bridge.command_finish(argparse.Namespace(id=room_id))
                self.assertFalse(directory.exists())
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                bridge.safe_remove_room(directory)
                if previous_home is None:
                    os.environ.pop("SESSION_BRIDGE_HOME", None)
                else:
                    os.environ["SESSION_BRIDGE_HOME"] = previous_home
                if previous_disable_keychain is None:
                    os.environ.pop("SESSION_BRIDGE_DISABLE_KEYCHAIN", None)
                else:
                    os.environ["SESSION_BRIDGE_DISABLE_KEYCHAIN"] = previous_disable_keychain


if __name__ == "__main__":
    unittest.main()
