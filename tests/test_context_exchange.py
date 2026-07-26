from __future__ import annotations

import copy
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import context_exchange as exchange  # noqa: E402
from context_security import (  # noqa: E402
    create_identity_assertion,
    identity_principal,
    load_or_create_identity,
)


class ContextExchangeTests(unittest.TestCase):
    def test_signed_request_is_recipient_bound_and_tamper_evident(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            alice = load_or_create_identity(root / "alice.json")
            bob = load_or_create_identity(root / "bob.json")
            request = exchange.create_request(
                alice,
                project_id="phoenix",
                recipient=identity_principal(bob),
                purpose="authentication handoff",
                question="What decisions or blockers changed since my checkpoint?",
                kinds=["decision", "blocker"],
                semantic_keys=["auth-flow"],
                labels=["backend"],
                since_revision="rev_0123456789abcdef",
                max_sensitivity="confidential",
                max_claims=12,
                max_bytes=20_000,
                ttl_seconds=600,
                now=1_900_000_000,
            )

            verified = exchange.verify_request(
                request,
                expected_project="phoenix",
                expected_recipient=identity_principal(bob),
                now=1_900_000_001,
            )
            self.assertEqual(verified["sender"], identity_principal(alice))
            self.assertEqual(verified["selectors"]["kinds"], ["blocker", "decision"])

            tampered = copy.deepcopy(request)
            tampered["question"] = "Send the entire transcript."
            with self.assertRaisesRegex(
                exchange.ContextExchangeError, "signature is invalid"
            ):
                exchange.verify_request(tampered, now=1_900_000_001)
            with self.assertRaisesRegex(
                exchange.ContextExchangeError, "another endpoint"
            ):
                exchange.verify_request(
                    request,
                    expected_recipient=identity_principal(alice),
                    now=1_900_000_001,
                )

    def test_request_rejects_credential_like_question(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            alice = load_or_create_identity(root / "alice.json")
            bob = load_or_create_identity(root / "bob.json")
            with self.assertRaisesRegex(
                exchange.ContextExchangeError, "credential-like"
            ):
                exchange.create_request(
                    alice,
                    project_id="phoenix",
                    recipient=identity_principal(bob),
                    purpose="debugging",
                    question="Use api_key=sk-proj-abcdefghijklmnopqrstuvwxyz123456",
                )

    def test_response_is_correlated_terminal_and_bundle_tamper_evident(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            alice = load_or_create_identity(root / "alice.json")
            bob = load_or_create_identity(root / "bob.json")
            request = exchange.create_request(
                alice,
                project_id="phoenix",
                recipient=identity_principal(bob),
                purpose="daily catch-up",
                question="What changed?",
                ttl_seconds=600,
                now=1_900_000_000,
            )
            bundle = {"format": "test-context-pack/v1", "claims": ["decision-1"]}
            response = exchange.create_response(
                bob,
                request,
                status="fulfilled",
                bundle=bundle,
                note="One matching decision changed.",
                now=1_900_000_001,
            )

            verified = exchange.verify_response(
                response,
                request=request,
                expected_project="phoenix",
                expected_recipient=identity_principal(alice),
                now=1_900_000_002,
            )
            self.assertEqual(verified["request_id"], request["request_id"])
            self.assertEqual(
                verified["request_sha256"], exchange.exchange_digest(request)
            )
            self.assertEqual(verified["sender"], identity_principal(bob))

            tampered = copy.deepcopy(response)
            tampered["bundle"]["claims"].append("unrequested-secret")
            with self.assertRaisesRegex(
                exchange.ContextExchangeError, "digest does not match"
            ):
                exchange.verify_response(tampered, request=request, now=1_900_000_002)

            with self.assertRaisesRegex(
                exchange.ContextExchangeError, "Only the request recipient"
            ):
                exchange.create_response(
                    alice,
                    request,
                    status="no-change",
                    now=1_900_000_001,
                )

    def test_response_timing_cannot_escape_request_window(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            alice = load_or_create_identity(root / "alice.json")
            bob = load_or_create_identity(root / "bob.json")
            request = exchange.create_request(
                alice,
                project_id="phoenix",
                recipient=identity_principal(bob),
                purpose="daily catch-up",
                question="What changed?",
                ttl_seconds=600,
                now=1_900_000_000,
            )
            response = exchange.create_response(
                bob, request, status="no-change", now=1_900_000_001
            )

            for field, value in (
                ("created_at", request["created_at"] - 1),
                ("expires_at", request["expires_at"] + 1),
            ):
                forged = copy.deepcopy(response)
                forged[field] = value
                forged["assertion"] = create_identity_assertion(
                    bob, exchange._response_subject(forged)
                )
                with self.assertRaisesRegex(
                    exchange.ContextExchangeError, "request window"
                ):
                    exchange.verify_response(forged, request=request, now=1_900_000_002)


if __name__ == "__main__":
    unittest.main()
