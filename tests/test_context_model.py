from __future__ import annotations

from pathlib import Path
import copy
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import context_model as model  # noqa: E402


TIME = "2026-07-22T03:00:00Z"
LATER = "2026-07-23T03:00:00Z"
AUTHOR = [{"principal_id": "did:key:alice", "display_name": "Alice", "role": "owner"}]
GOVERNANCE = {
    "owner_principal_id": "did:key:alice",
    "visibility": "scoped",
    "share_policy": "owner_approval",
    "recipients": ["did:key:bob"],
}


def source(kind: str = "repository_file") -> list[dict[str, str]]:
    return [
        {
            "type": kind,
            "uri": "repo://app/verify.py",
            "digest": "sha256:" + "a" * 64,
            "observed_at": TIME,
        }
    ]


def claim(
    identifier: str, statement: str, key: str, *, expiry: str | None = None
) -> dict[str, object]:
    return model.make_claim(
        identifier,
        "fact",
        statement,
        key,
        source(),
        confidence="confirmed",
        observed_at=TIME,
        expires_at=expiry,
    )


def revision(
    identifier: str, sequence: int, parents: list[str], claims: list[dict[str, object]]
) -> dict[str, object]:
    return model.create_revision(
        "pack-phoenix",
        identifier,
        sequence,
        parents,
        claims,
        AUTHOR,
        GOVERNANCE,
        "record context",
        created_at=TIME,
    )


class ContextModelTests(unittest.TestCase):
    def test_canonical_digest_is_stable_across_key_order(self) -> None:
        self.assertEqual(
            model.digest({"b": 1, "a": [2]}), model.digest({"a": [2], "b": 1})
        )

    def test_revision_is_immutable_and_digest_validates(self) -> None:
        record = revision(
            "rev-one",
            1,
            [],
            [claim("claim-one", "Raw body is required.", "webhook-body")],
        )
        model.validate_revision(record, {"rev-one": record})
        tampered = copy.deepcopy(record)
        tampered["claims"][0]["statement"] = "Tampered evidence."
        with self.assertRaisesRegex(model.ContextValidationError, "digest mismatch"):
            model.validate_revision(tampered, {"rev-one": tampered})

    def test_claim_requires_typed_provenance_and_confirmed_evidence(self) -> None:
        bad = claim("claim-one", "Raw body is required.", "webhook-body")
        bad["provenance"] = [
            {"type": "human_statement", "uri": "human://alice", "observed_at": TIME}
        ]
        with self.assertRaises(model.ContextValidationError):
            model.validate_claim(bad)

    def test_parent_sequence_and_depth_are_enforced(self) -> None:
        first = revision("rev-one", 1, [], [])
        second = revision("rev-two", 2, ["rev-one"], [])
        model.validate_revision(second, {"rev-one": first, "rev-two": second})
        wrong = revision("rev-wrong", 4, ["rev-one"], [])
        with self.assertRaisesRegex(model.ContextValidationError, "sequence"):
            model.validate_revision(wrong, {"rev-one": first, "rev-wrong": wrong})

    def test_expired_claim_is_not_active_without_mutating_history(self) -> None:
        record = revision(
            "rev-one",
            1,
            [],
            [
                claim(
                    "claim-one",
                    "Rotates weekly.",
                    "rotation",
                    expiry="2026-07-22T04:00:00Z",
                )
            ],
        )
        view = model.resolved_active_view([record], LATER)
        self.assertEqual(view["active_claims"], [])
        self.assertEqual(view["historical_claims"][0]["effective_status"], "expired")
        self.assertEqual(record["claims"][0]["status"], "active")

    def test_semantic_diff_is_deterministic(self) -> None:
        first = revision(
            "rev-one", 1, [], [claim("claim-one", "Use raw body.", "webhook-body")]
        )
        second = revision(
            "rev-two",
            2,
            ["rev-one"],
            [
                claim("claim-one", "Use raw body.", "webhook-body"),
                claim(
                    "claim-two", "Reject malformed signatures.", "signature-validation"
                ),
            ],
        )
        result = model.semantic_diff([first], [first, second], TIME)
        self.assertEqual([item["id"] for item in result["added"]], ["claim-two"])
        self.assertEqual(result["changed"], [])

    def test_supersession_is_a_visible_lifecycle_transition(self) -> None:
        old = claim("claim-old", "Use version one.", "api-version")
        first = revision("rev-one", 1, [], [old])
        new = claim("claim-new", "Use version two.", "api-version")
        new["supersedes"] = ["claim-old"]
        second = revision("rev-two", 2, ["rev-one"], [new])
        view = model.resolved_active_view([first, second], TIME)
        self.assertEqual([item["id"] for item in view["active_claims"]], ["claim-new"])
        self.assertEqual(view["historical_claims"][0]["effective_status"], "superseded")
        delta = model.semantic_diff([first], [first, second], TIME)
        self.assertIn(
            {"id": "claim-old", "before": "active", "after": "superseded"},
            delta["lifecycle"],
        )

    def test_merge_plan_never_silently_selects_divergent_claims(self) -> None:
        local = revision(
            "rev-local",
            1,
            [],
            [claim("claim-local", "Verify raw body.", "webhook-body")],
        )
        remote = revision(
            "rev-remote",
            1,
            [],
            [claim("claim-remote", "Verify parsed JSON.", "webhook-body")],
        )
        plan = model.plan_merge([local], [remote], TIME)
        self.assertFalse(plan["mergeable"])
        self.assertEqual(plan["conflicts"][0]["semantic_key"], "webhook-body")
        self.assertEqual(plan["auto_claims"], [])

    def test_merge_auto_accepts_disjoint_claims(self) -> None:
        local = revision(
            "rev-local",
            1,
            [],
            [claim("claim-local", "Verify raw body.", "webhook-body")],
        )
        remote = revision(
            "rev-remote",
            1,
            [],
            [claim("claim-remote", "Add replay test.", "replay-test")],
        )
        plan = model.plan_merge([local], [remote], TIME)
        self.assertTrue(plan["mergeable"])
        self.assertEqual(
            [item["id"] for item in plan["auto_claims"]],
            ["claim-local", "claim-remote"],
        )

    def test_byte_limit_and_malformed_digest_are_rejected(self) -> None:
        record = revision("rev-one", 1, [], [])
        record["integrity"]["canonical_sha256"] = "sha256:not-a-real-digest"
        with self.assertRaisesRegex(model.ContextValidationError, "digest mismatch"):
            model.validate_revision(record)

    def test_provenance_and_artifact_digests_require_exact_sha256(self) -> None:
        bad_claim = claim("claim-bad-digest", "Evidence exists.", "evidence")
        bad_claim["provenance"][0]["digest"] = "sha256:not-hex"
        with self.assertRaisesRegex(model.ContextValidationError, "sha256"):
            model.validate_claim(bad_claim)
        with self.assertRaisesRegex(model.ContextValidationError, "sha256"):
            model.create_revision(
                "pack-phoenix",
                "rev-artifact",
                1,
                [],
                [],
                AUTHOR,
                GOVERNANCE,
                "bad artifact",
                artifacts=[
                    {
                        "id": "artifact-one",
                        "media_type": "application/json",
                        "uri": "repo://artifact",
                        "digest": "sha256:also-not-hex",
                    }
                ],
                created_at=TIME,
            )


if __name__ == "__main__":
    unittest.main()
