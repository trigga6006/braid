from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest


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


if __name__ == "__main__":
    unittest.main()
