from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import tempfile
import time
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import context_security as security  # noqa: E402


class ContextSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = int(time.time())
        self.policy = "a" * 64

    def test_persistent_identity_and_signed_export_is_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            identity = security.load_or_create_identity(
                Path(directory) / "identity.json"
            )
            self.assertEqual(
                identity,
                security.load_or_create_identity(Path(directory) / "identity.json"),
            )
            exported = security.sign_export(
                {"claims": ["tested"]},
                identity,
                project="acme",
                scope="review",
                recipient="device-1",
                policy_digest=self.policy,
                policy_version=1,
                expires_at=self.now + 60,
            )
            verified = security.verify_export(
                exported,
                trusted_keys={identity.key_id: identity.public_key},
                project="acme",
                scope="review",
                recipient="device-1",
                policy_digest=self.policy,
            )
            self.assertIsInstance(verified, security.QuarantinedExport)
            self.assertEqual(verified.export["revision"]["claims"], ["tested"])

    def test_identity_assertion_is_key_derived_and_subject_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            identity = security.load_or_create_identity(
                Path(directory) / "identity.json"
            )
            subject = {"role": "join", "room_id": "room-1", "expires": self.now + 60}
            assertion = security.create_identity_assertion(identity, subject)
            self.assertEqual(
                security.verify_identity_assertion(assertion, subject),
                security.identity_principal(identity),
            )
            with self.assertRaisesRegex(security.SecurityError, "subject mismatch"):
                security.verify_identity_assertion(
                    assertion, {**subject, "room_id": "attacker-room"}
                )
            assertion["subject"]["role"] = "host"
            with self.assertRaisesRegex(security.SecurityError, "signature failed"):
                security.verify_identity_assertion(assertion, assertion["subject"])

    def test_concurrent_identity_bootstrap_has_one_persistent_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recipient.json"
            with ThreadPoolExecutor(max_workers=16) as executor:
                identities = list(
                    executor.map(
                        lambda _: security.load_or_create_identity(path), range(32)
                    )
                )
            self.assertEqual(
                {item.key_id for item in identities}, {identities[0].key_id}
            )
            self.assertEqual(
                security.load_or_create_identity(path).key_id, identities[0].key_id
            )

    def test_signature_boundary_revocation_and_recipient_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            identity = security.load_or_create_identity(Path(directory) / "id")
            exported = security.sign_export(
                {"fact": "x"},
                identity,
                project="p",
                scope="s",
                recipient="r",
                policy_digest=self.policy,
                policy_version=1,
                expires_at=self.now + 60,
            )
            exported["revision"]["fact"] = "forged"
            with self.assertRaises(security.SecurityError):
                security.verify_export(
                    exported, trusted_keys={identity.key_id: identity.public_key}
                )
            exported = security.sign_export(
                {"fact": "x"},
                identity,
                project="p",
                scope="s",
                recipient="r",
                policy_digest=self.policy,
                policy_version=1,
                expires_at=self.now + 60,
            )
            with self.assertRaises(security.SecurityError):
                security.verify_export(
                    exported,
                    trusted_keys={identity.key_id: identity.public_key},
                    recipient="other",
                )
            with self.assertRaises(security.SecurityError):
                security.verify_export(exported, revoked_keys={identity.key_id})

    def test_exact_non_delegable_disclosure_grant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            identity = security.load_or_create_identity(Path(directory) / "id")
            pack = "b" * 64
            grant = security.create_disclosure_grant(
                identity,
                pack_digest=pack,
                project="p",
                scope="s",
                recipient="r",
                policy_digest=self.policy,
                policy_version=2,
                expires_at=self.now + 60,
                operations=("read", "merge"),
            )
            security.verify_disclosure_grant(
                grant,
                pack_digest=pack,
                project="p",
                scope="s",
                recipient="r",
                policy_digest=self.policy,
                min_policy_version=2,
                required_operation="merge",
                trusted_keys={identity.key_id: identity.public_key},
            )
            with self.assertRaises(security.SecurityError):
                security.verify_disclosure_grant(
                    grant,
                    pack_digest=pack,
                    project="p",
                    scope="s",
                    recipient="other",
                    policy_digest=self.policy,
                    min_policy_version=2,
                    trusted_keys={identity.key_id: identity.public_key},
                )
            with self.assertRaises(security.SecurityError):
                security.create_disclosure_grant(
                    identity,
                    pack_digest=pack,
                    project="p",
                    scope="s",
                    recipient="r",
                    policy_digest=self.policy,
                    policy_version=2,
                    expires_at=self.now + 60,
                    delegable=True,
                )

    def test_policy_rejects_rollback_and_equivocation(self) -> None:
        tracker = security.PolicyVersionStore()
        tracker.accept("p", 2, self.policy)
        with self.assertRaises(security.SecurityError):
            tracker.accept("p", 1, self.policy)
        with self.assertRaises(security.SecurityError):
            tracker.accept("p", 2, "b" * 64)

    def test_dlp_redaction_and_strict_parser(self) -> None:
        source = {
            "nested": [{"api_key": "sk-proj-abcdefghijklmnopqrstuvwx"}],
            "note": "safe",
        }
        findings = security.scan_sensitive(source)
        redacted, redacted_findings = security.redact_sensitive(source)
        self.assertTrue(findings)
        self.assertEqual(findings, redacted_findings)
        self.assertEqual(redacted["nested"][0]["api_key"], "[REDACTED]")
        with self.assertRaises(security.SecurityError):
            security.strict_json_loads('{"a": 1, "a": 2}')
        with self.assertRaises(security.SecurityError):
            security.strict_json_loads('{"unknown": true}', allowed_fields={"allowed"})

    def test_shape_limits_and_unknown_critical_fields_fail_closed(self) -> None:
        with self.assertRaises(security.SecurityError):
            security.validate_json_value([[[["x"]]]], max_depth=2)
        with tempfile.TemporaryDirectory() as directory:
            identity = security.load_or_create_identity(Path(directory) / "id")
            exported = security.sign_export(
                {"x": 1},
                identity,
                project="p",
                scope="s",
                recipient="r",
                policy_digest=self.policy,
                policy_version=1,
                expires_at=self.now + 60,
            )
            exported["surprise"] = True
            with self.assertRaises(security.SecurityError):
                security.verify_export(exported)


if __name__ == "__main__":
    unittest.main()
