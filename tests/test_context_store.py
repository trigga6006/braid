from __future__ import annotations
import hashlib
import json
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path
import sys

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
from context_model import canonical_json, create_revision, digest, make_claim  # noqa: E402
from context_security import (  # noqa: E402
    create_disclosure_grant,
    digest as security_digest,
    load_or_create_identity,
    sign_export,
)
from context_store import ContextLedger, _atomic_json  # noqa: E402


def claim(identifier="claim-1"):
    return make_claim(
        identifier,
        "fact",
        "A verified test passed",
        "test-status",
        [
            {
                "type": "test_result",
                "uri": "local:test",
                "observed_at": "2026-07-22T00:00:00Z",
            }
        ],
        confidence="confirmed",
    )


def approve_stage(ledger: ContextLedger, claims, message=""):
    staged = ledger.stage(claims, message)
    review = ledger.review_staged(staged["stage_id"])
    ledger.approve_staged(staged["stage_id"], review["review_digest"])
    return staged


def write_signed_bundle(
    sender: ContextLedger,
    receiver: ContextLedger,
    incoming_claim: dict,
    path: Path,
) -> None:
    identity = load_or_create_identity(sender.identity_path)
    governance = {
        "owner_principal_id": identity.key_id,
        "visibility": "scoped",
        "share_policy": "owner_approval",
        "recipients": [receiver.principal],
    }
    revision = create_revision(
        sender.pack_id,
        "r-" + hashlib.sha256(incoming_claim["id"].encode()).hexdigest()[:24],
        1,
        [],
        [incoming_claim],
        [{"principal_id": identity.key_id, "display_name": "test", "role": "owner"}],
        governance,
        "signed test disclosure",
    )
    policy_digest = hashlib.sha256(canonical_json(governance)).hexdigest()
    expires = int(time.time()) + 3600
    signed = sign_export(
        revision,
        identity,
        project=sender.pack_id,
        scope=sender.pack_id,
        recipient=receiver.principal,
        policy_digest=policy_digest,
        policy_version=1,
        expires_at=expires,
    )
    grant = create_disclosure_grant(
        identity,
        pack_digest=security_digest(revision),
        project=sender.pack_id,
        scope=sender.pack_id,
        recipient=receiver.principal,
        policy_digest=policy_digest,
        policy_version=1,
        expires_at=expires,
    )
    _atomic_json(
        path,
        {"format": "context-disclosure/v1", "export": signed, "grant": grant},
    )


class LedgerTests(unittest.TestCase):
    def test_principal_alias_cannot_override_endpoint_identity(self):
        with tempfile.TemporaryDirectory() as home:
            ledger = ContextLedger("identity", Path(home))
            self.assertTrue(ledger.principal.startswith("ed25519:"))
            with self.assertRaisesRegex(ValueError, "recipient key"):
                ContextLedger("identity", Path(home), "team:admin")

    def test_stage_commit_audit_disclosure_and_revoke(self):
        with tempfile.TemporaryDirectory() as home:
            ledger = ContextLedger("demo", Path(home))
            staged = ledger.stage([claim()], "initial")
            with self.assertRaises(PermissionError):
                ledger.commit("alice", stage_id=staged["stage_id"])
            review = ledger.review_staged(staged["stage_id"])
            ledger.approve_staged(staged["stage_id"], review["review_digest"])
            revision = ledger.commit("alice", stage_id=staged["stage_id"])
            self.assertEqual(ledger.status()["heads"], [revision["id"]])
            self.assertTrue(ledger.verify_audit())
            ledger.disclose("bob", revision["id"])
            self.assertEqual(ledger.who_has_claim("claim-1"), ["bob"])
            ledger.revoke("claim-1", "superseded")
            with self.assertRaises(PermissionError):
                ledger.disclose("carol", revision["id"])

    def test_export_is_quarantined_before_acceptance(self):
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            first = ContextLedger("demo", root)
            second = ContextLedger("other", root)
            approve_stage(first, [claim()], "initial")
            revision = first.commit("alice")
            export = root / "portable.json"
            first.export(revision["id"], export, recipient=second.principal)
            token = second.import_quarantine(export)
            self.assertEqual(second.log(), [])
            review = second.review_import(token)
            self.assertEqual(review["claim_count"], 1)
            self.assertEqual(review["claims"][0]["statement"], "A verified test passed")
            self.assertEqual(review["recipient"], second.principal)
            accepted = second.accept_import(token)
            self.assertEqual(second.show(accepted["id"])["id"], accepted["id"])
            self.assertEqual(len(second.status()["trusted_author_keys"]), 1)

    def test_diff_uses_ancestry_and_freshness_applies_local_revocation(self):
        with tempfile.TemporaryDirectory() as home:
            ledger = ContextLedger("demo", Path(home))
            approve_stage(ledger, [claim("claim-1")])
            first = ledger.commit("alice")
            approve_stage(ledger, [claim("claim-2")])
            second = ledger.commit("alice")
            self.assertEqual(
                [
                    item["id"]
                    for item in ledger.diff(first["id"], second["id"])["added"]
                ],
                ["claim-2"],
            )
            ledger.revoke("claim-1", "withdrawn")
            view = ledger.freshness("2026-07-22T01:00:00Z")
            self.assertEqual(
                [item["id"] for item in view["active_claims"]], ["claim-2"]
            )
            self.assertEqual(
                {
                    item["id"]: item["effective_status"]
                    for item in view["historical_claims"]
                },
                {"claim-1": "revoked"},
            )

    def test_signed_export_tampering_is_rejected_before_quarantine(self):
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            first = ContextLedger("demo", root)
            approve_stage(first, [claim()])
            revision = first.commit("alice")
            export = root / "portable.json"
            receiver = ContextLedger("other", root)
            first.export(revision["id"], export, recipient=receiver.principal)
            import json

            value = json.loads(export.read_text(encoding="utf-8"))
            value["export"]["revision"]["claims"][0]["statement"] = "tampered"
            export.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Invalid signed disclosure"):
                ContextLedger("other", root).import_quarantine(export)

    def test_disclosure_grant_issuer_must_match_export_author(self):
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            sender = ContextLedger("issuer-source", root / "sender")
            receiver = ContextLedger("issuer-target", root / "receiver")
            path = root / "mixed-issuer.json"
            write_signed_bundle(sender, receiver, claim("claim-mixed"), path)
            value = json.loads(path.read_text(encoding="utf-8"))
            signed = value["export"]
            rogue = load_or_create_identity(root / "rogue-identity.json")
            value["grant"] = create_disclosure_grant(
                rogue,
                pack_digest=security_digest(signed["revision"]),
                project=signed["project"],
                scope=signed["scope"],
                recipient=receiver.principal,
                policy_digest=signed["policy_digest"],
                policy_version=signed["policy_version"],
                expires_at=signed["expires_at"],
            )
            _atomic_json(path, value)
            with self.assertRaisesRegex(ValueError, "issuer.*author"):
                receiver.import_quarantine(path)

    def test_untrusted_import_read_is_bounded_before_json_parse(self):
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            oversized = root / "oversized.json"
            oversized.write_bytes(b"{" + b"x" * 2_000_000 + b"}")
            with self.assertRaisesRegex(ValueError, "2 MB"):
                ContextLedger("bounded-import", root).import_quarantine(oversized)

    def test_tampered_audit_chain_is_detected(self):
        with tempfile.TemporaryDirectory() as home:
            ledger = ContextLedger("demo", Path(home))
            approve_stage(ledger, [claim()])
            ledger.commit("alice")
            ledger.audit_path.write_text('{"bad":true}\n', encoding="utf-8")
            self.assertFalse(ledger.verify_audit())

    def test_malformed_audit_tail_fails_closed_without_mutation(self):
        with tempfile.TemporaryDirectory() as home:
            ledger = ContextLedger("audit-tail", Path(home))
            ledger.audit_path.write_text('{"partial":', encoding="utf-8")
            self.assertFalse(ledger.verify_audit())
            self.assertFalse(ledger.status()["audit_valid"])
            with self.assertRaisesRegex(ValueError, "Audit chain is invalid"):
                ledger.stage([claim()])
            self.assertEqual(list(ledger.staging.glob("*.json")), [])

    def test_hash_valid_semantically_malformed_audit_fails_closed(self):
        malformed_entries = [
            {
                "at": "2026-07-22T00:00:00Z",
                "details": {},
                "previous": "",
            },
            {
                "at": "2026-07-22T00:00:00Z",
                "action": "unknown-action",
                "details": {},
                "previous": "",
            },
            {
                "at": "2026-07-22T00:00:00Z",
                "action": "stage",
                "details": {
                    "stage_id": "s-" + "a" * 24,
                    "claims": 1,
                    "reviewed": False,
                    "digest": "sha256:" + "a" * 64,
                },
                "previous": "",
            },
            {
                "at": "2026-07-22T00:00:00Z",
                "action": "review-stage",
                "details": {
                    "stage_id": "s-" + "a" * 24,
                    "claims": "one",
                    "digest": "sha256:" + "a" * 64,
                },
                "previous": "",
            },
        ]
        for malformed in malformed_entries:
            with self.subTest(action=malformed.get("action")):
                with tempfile.TemporaryDirectory() as home:
                    ledger = ContextLedger("audit-schema", Path(home))
                    malformed["hash"] = digest(malformed)
                    ledger.audit_path.write_bytes(canonical_json(malformed) + b"\n")
                    self.assertFalse(ledger.verify_audit())
                    with self.assertRaisesRegex(ValueError, "Audit chain is invalid"):
                        ledger.stage([claim()])
                    self.assertEqual(list(ledger.staging.glob("*.json")), [])

    def test_duplicate_key_audit_entry_fails_closed(self):
        with tempfile.TemporaryDirectory() as home:
            ledger = ContextLedger("audit-duplicate", Path(home))
            ledger.audit_path.write_text(
                '{"at":"2026-07-22T00:00:00Z","at":"2026-07-22T00:00:00Z",'
                '"action":"review-stage","details":{},"previous":"",'
                '"hash":"sha256:' + "a" * 64 + '"}\n',
                encoding="utf-8",
            )
            self.assertFalse(ledger.verify_audit())
            with self.assertRaisesRegex(ValueError, "Audit chain is invalid"):
                ledger.stage([claim()])

    def test_audit_write_failure_before_transition_leaves_state_unchanged(self):
        with tempfile.TemporaryDirectory() as home:
            ledger = ContextLedger("audit-write", Path(home))
            with mock.patch.object(ledger, "_audit", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    ledger.stage([claim()])
            self.assertEqual(list(ledger.staging.glob("*.json")), [])
            self.assertEqual(ledger.status()["heads"], [])

    def test_incomplete_post_transition_audit_is_visible_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as home:
            ledger = ContextLedger("audit-intent", Path(home))
            staged = approve_stage(ledger, [claim()])
            original = ledger._audit

            def fail_final(action, details):
                if action == "commit":
                    raise OSError("audit append failed")
                return original(action, details)

            with mock.patch.object(ledger, "_audit", side_effect=fail_final):
                with self.assertRaises(OSError):
                    ledger.commit("alice", stage_id=staged["stage_id"])
            self.assertEqual(len(ledger._state()["heads"]), 1)
            self.assertFalse(ledger.verify_audit())
            with self.assertRaisesRegex(ValueError, "Audit chain is invalid"):
                ledger.stage([claim("claim-later")])

    def test_stages_are_isolated_and_review_is_enforced(self):
        with tempfile.TemporaryDirectory() as home:
            ledger = ContextLedger("parallel", Path(home))
            one = ledger.stage([claim("claim-1")])
            two = ledger.stage([claim("claim-2")])
            self.assertNotEqual(one["stage_id"], two["stage_id"])
            with self.assertRaisesRegex(ValueError, "Multiple stages"):
                ledger.commit("alice")
            review = ledger.review_staged(one["stage_id"])
            ledger.approve_staged(one["stage_id"], review["review_digest"])
            first = ledger.commit("alice", stage_id=one["stage_id"])
            review = ledger.review_staged(two["stage_id"])
            ledger.approve_staged(two["stage_id"], review["review_digest"])
            second = ledger.commit("alice", stage_id=two["stage_id"])
            self.assertEqual(second["revision"]["parent_ids"], [first["id"]])

    def test_recipient_binding_rejects_replay_to_another_principal(self):
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            sender = ContextLedger("sender", root / "sender-home")
            bob = ContextLedger("bob", root / "bob-home")
            carol = ContextLedger("carol", root / "carol-home")
            approve_stage(sender, [claim()])
            revision = sender.commit("alice")
            path = root / "for-bob.json"
            sender.export(revision["id"], path, recipient=bob.principal)
            with self.assertRaisesRegex(ValueError, "recipient"):
                carol.import_quarantine(path)

    def test_missing_parent_never_becomes_a_head(self):
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            sender = ContextLedger("malicious-source", root / "sender-home")
            receiver = ContextLedger("target", root / "receiver-home")
            identity = load_or_create_identity(sender.identity_path)
            governance = {
                "owner_principal_id": identity.key_id,
                "visibility": "scoped",
                "share_policy": "owner_approval",
                "recipients": [receiver.principal],
            }
            revision = create_revision(
                sender.pack_id,
                "r-missing-parent",
                2,
                ["r-does-not-exist"],
                [claim()],
                [
                    {
                        "principal_id": identity.key_id,
                        "display_name": "test",
                        "role": "owner",
                    }
                ],
                governance,
                "invalid ancestry",
            )
            policy_digest = hashlib.sha256(canonical_json(governance)).hexdigest()
            expires = int(time.time()) + 3600
            signed = sign_export(
                revision,
                identity,
                project=sender.pack_id,
                scope=sender.pack_id,
                recipient=receiver.principal,
                policy_digest=policy_digest,
                policy_version=1,
                expires_at=expires,
            )
            grant = create_disclosure_grant(
                identity,
                pack_digest=security_digest(revision),
                project=sender.pack_id,
                scope=sender.pack_id,
                recipient=receiver.principal,
                policy_digest=policy_digest,
                policy_version=1,
                expires_at=expires,
            )
            path = root / "missing-parent.json"
            _atomic_json(
                path,
                {"format": "context-disclosure/v1", "export": signed, "grant": grant},
            )
            orphan = create_revision(
                receiver.pack_id,
                "r-does-not-exist",
                1,
                [],
                [claim("claim-orphan")],
                [
                    {
                        "principal_id": "orphan",
                        "display_name": "orphan",
                        "role": "owner",
                    }
                ],
                {
                    "owner_principal_id": "orphan",
                    "visibility": "private",
                    "share_policy": "owner_approval",
                    "recipients": [],
                },
                "unreachable orphan",
            )
            _atomic_json(receiver.commits / "r-does-not-exist.json", orphan)
            # A signed disclosure that grafts onto local history (any non-root
            # revision) is rejected at import, before it can be quarantined,
            # accepted, or silently supersede a local claim.
            with self.assertRaisesRegex(ValueError, "independent root"):
                receiver.import_quarantine(path)
            self.assertEqual(receiver.status()["heads"], [])
            self.assertEqual(receiver.log(), [])

    def test_policy_rollback_is_rejected_before_commit_persistence(self):
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            sender = ContextLedger("policy-source", root / "sender-home")
            receiver = ContextLedger("policy-target", root / "receiver-home")
            state = sender._state()
            state["policy_version"] = 2
            _atomic_json(sender.state_path, state)
            approve_stage(sender, [claim("claim-v2")])
            first = sender.commit("alice")
            first_path = root / "policy-v2.json"
            sender.export(first["id"], first_path, recipient=receiver.principal)
            token = receiver.import_quarantine(first_path)
            receiver.review_import(token)
            receiver.accept_import(token)

            state = sender._state()
            state["policy_version"] = 1
            _atomic_json(sender.state_path, state)
            approve_stage(sender, [claim("claim-v1")])
            second = sender.commit("alice")
            second_path = root / "policy-v1.json"
            sender.export(second["id"], second_path, recipient=receiver.principal)
            rejected_id = json.loads(second_path.read_text(encoding="utf-8"))["export"][
                "revision"
            ]["id"]
            token = receiver.import_quarantine(second_path)
            receiver.review_import(token)
            with self.assertRaisesRegex(PermissionError, "rollback"):
                receiver.accept_import(token)
            self.assertFalse((receiver.commits / f"{rejected_id}.json").exists())
            self.assertNotIn(rejected_id, [item["id"] for item in receiver.log()])

    def test_credential_assignment_is_blocked_before_staging(self):
        with tempfile.TemporaryDirectory() as home:
            bad = claim()
            bad["statement"] = "Database password=CorrectHorseBatteryStaple"
            with self.assertRaisesRegex(ValueError, "Credential-like"):
                ContextLedger("secret", Path(home)).stage([bad])

    def test_sensitive_import_review_is_redacted_and_bundle_is_review_bound(self):
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            sender = ContextLedger("secret-source", root / "sender")
            receiver = ContextLedger("secret-target", root / "receiver")
            secret = claim("claim-secret")
            secret["statement"] = "API key=sk-proj-abcdefghijklmnopqrstuvwx"
            secret["sensitivity"] = "restricted"
            path = root / "secret.json"
            write_signed_bundle(sender, receiver, secret, path)
            token = receiver.import_quarantine(path)

            quarantined_path = receiver.quarantine / f"{token}.json"
            cached = json.loads(quarantined_path.read_text(encoding="utf-8"))
            cached["review"]["claims"][0]["statement"] = "A harmless lie"
            _atomic_json(quarantined_path, cached)
            review = receiver.review_import(token)
            rendered = json.dumps(review)
            self.assertNotIn("sk-proj-abcdefghijklmnopqrstuvwx", rendered)
            self.assertIn("[REDACTED]", rendered)
            self.assertTrue(review["security_findings"])
            with self.assertRaisesRegex(PermissionError, "explicit override"):
                receiver.accept_import(token)

            tampered = json.loads(quarantined_path.read_text(encoding="utf-8"))
            tampered["bundle"]["export"]["revision"]["claims"][0]["statement"] = (
                "changed after review"
            )
            _atomic_json(quarantined_path, tampered)
            with self.assertRaisesRegex(PermissionError, "changed after review"):
                receiver.accept_import(token, allow_sensitive=True)

    def test_third_independent_head_stays_quarantined(self):
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            receiver = ContextLedger("head-target", root / "receiver-home")
            tokens = []
            for index in range(3):
                sender = ContextLedger(f"head-source-{index}", root / f"sender-{index}")
                approve_stage(sender, [claim(f"claim-head-{index}")])
                revision = sender.commit("alice")
                path = root / f"head-{index}.json"
                sender.export(revision["id"], path, recipient=receiver.principal)
                token = receiver.import_quarantine(path)
                receiver.review_import(token)
                tokens.append(token)
            receiver.accept_import(tokens[0])
            receiver.accept_import(tokens[1])
            with self.assertRaisesRegex(PermissionError, "already has two heads"):
                receiver.accept_import(tokens[2])
            self.assertEqual(len(receiver.status()["heads"]), 2)
            self.assertEqual(receiver.status()["quarantined"], 1)

    def test_two_divergent_heads_require_explicit_conflict_preservation(self):
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            receiver = ContextLedger("merge-target", root / "receiver")
            for index, statement in enumerate(("Use Postgres.", "Use SQLite.")):
                sender = ContextLedger(
                    f"merge-source-{index}", root / f"sender-{index}"
                )
                divergent = make_claim(
                    f"claim-db-{index}",
                    "decision",
                    statement,
                    "database",
                    [
                        {
                            "type": "test_result",
                            "uri": f"test://database/{index}",
                            "observed_at": "2026-07-22T00:00:00Z",
                        }
                    ],
                )
                approve_stage(sender, [divergent])
                revision = sender.commit("alice")
                path = root / f"merge-{index}.json"
                sender.export(revision["id"], path, recipient=receiver.principal)
                token = receiver.import_quarantine(path)
                receiver.review_import(token)
                receiver.accept_import(token)

            ordinary = approve_stage(receiver, [claim("claim-unrelated")])
            with self.assertRaisesRegex(PermissionError, "require reconcile"):
                receiver.commit("owner", stage_id=ordinary["stage_id"])
            heads = receiver.status()["heads"]
            plan = receiver.prepare_reconciliation([heads[0]], [heads[1]])
            self.assertEqual(len(plan["conflicts"]), 1)
            self.assertEqual(len(receiver.conflicts()["conflicts"]), 1)
            disagreement = make_claim(
                "claim-db-conflict",
                "disagreement",
                "Postgres and SQLite remain unresolved alternatives.",
                "database",
                [
                    {
                        "type": "human_statement",
                        "uri": "review://merge-target/database",
                        "observed_at": "2026-07-22T00:00:00Z",
                    }
                ],
            )
            resolution = receiver.stage(
                [disagreement],
                "preserve database conflict",
                reconciliation_token=plan["reconciliation_token"],
            )
            review = receiver.review_staged(resolution["stage_id"])
            receiver.approve_staged(resolution["stage_id"], review["review_digest"])
            merged = receiver.commit("owner", stage_id=resolution["stage_id"])
            self.assertEqual(set(merged["revision"]["parent_ids"]), set(heads))
            self.assertEqual(len(receiver.status()["heads"]), 1)


if __name__ == "__main__":
    unittest.main()
