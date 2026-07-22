from __future__ import annotations
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from context_model import create_revision, make_claim  # noqa: E402
from context_policy import PolicyError, plan_disclosure  # noqa: E402


def claim(
    identifier: str,
    kind: str,
    text: str,
    *,
    sensitivity: str = "internal",
    audience=None,
):
    return make_claim(
        identifier,
        kind,
        text,
        identifier,
        [
            {
                "type": "test_result",
                "uri": "test:policy",
                "digest": "sha256:" + "1" * 64,
                "observed_at": "2026-07-22T00:00:00Z",
            }
        ],
        observed_at="2026-07-22T00:00:00Z",
        sensitivity=sensitivity,
        audience=audience or [],
    )


def revision(claims):
    return create_revision(
        "pack",
        "r1",
        1,
        [],
        claims,
        [{"principal_id": "alice", "display_name": "Alice", "role": "owner"}],
        {
            "owner_principal_id": "alice",
            "visibility": "private",
            "share_policy": "owner_approval",
            "recipients": [],
        },
        "initial",
        created_at="2026-07-22T00:00:00Z",
    )


class ContextPolicyTests(unittest.TestCase):
    def test_minimizes_by_clearance_audience_purpose_and_budget(self):
        pack = revision(
            [
                claim("block", "blocker", "Database migration blocks the release"),
                claim(
                    "secret",
                    "fact",
                    "Restricted acquisition plan",
                    sensitivity="restricted",
                ),
                claim("sales", "fact", "Sales pipeline changed", audience=["sales"]),
                claim("noise", "hypothesis", "Maybe redesign the dashboard"),
            ]
        )
        plan = plan_disclosure(
            [pack],
            {
                "principal_id": "bob",
                "purpose": "release migration",
                "max_sensitivity": "internal",
                "max_claims": 1,
                "max_bytes": 10000,
            },
        )
        self.assertEqual([item["id"] for item in plan["claims"]], ["block"])
        self.assertEqual(
            {item["claim_id"] for item in plan["excluded"]},
            {"secret", "sales", "noise"},
        )
        self.assertTrue(plan["requires_review"])

    def test_required_claim_fails_closed_when_policy_or_budget_excludes_it(self):
        pack = revision(
            [claim("secret", "fact", "Restricted plan", sensitivity="restricted")]
        )
        with self.assertRaises(PolicyError):
            plan_disclosure(
                [pack],
                {"principal_id": "bob", "max_sensitivity": "internal"},
                required_claim_ids=["secret"],
            )

    def test_secret_scanner_blocks_claim_without_leaking_secret(self):
        pack = revision(
            [claim("token", "fact", "Use bearer abcdefghijklmnopqrstuvwxyz123456")]
        )
        plan = plan_disclosure([pack], {"principal_id": "bob"})
        self.assertEqual(plan["claims"], [])
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", str(plan["excluded"]))


if __name__ == "__main__":
    unittest.main()
