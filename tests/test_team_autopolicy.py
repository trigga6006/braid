"""End-to-end standing authorization over the real hub and connector."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from context_store import ContextLedger  # noqa: E402
import context_autopolicy as autopolicy  # noqa: E402
import network_bridge as bridge  # noqa: E402
import team_connector as connector  # noqa: E402

from test_team_connector import (  # noqa: E402
    ConnectorHarness,
    committed_blocker,
    committed_retraction,
    committed_revision,
)


class AutoRespondTests(unittest.TestCase):
    """Two enrolled endpoints, one open request, no human in the loop."""

    def setUp(self) -> None:
        # Load the pinned cryptography copy while BRAID_HOME still points at
        # the real endpoint home; the temporary home below has no vendored one.
        bridge.crypto_imports()
        self._saved_home = os.environ.get("BRAID_HOME")
        self._saved_keychain = os.environ.get("BRAID_DISABLE_KEYCHAIN")
        os.environ["BRAID_DISABLE_KEYCHAIN"] = "1"
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)
        os.environ["BRAID_HOME"] = str(self.root / "shared-security")
        self.harness = ConnectorHarness(self.root)
        self.alice = self.harness.enroll("Alice", self.root / "alice")
        self.bob = self.harness.enroll("Bob", self.root / "bob")
        self.alice_principal = str(self.alice.load_config("phoenix")["principal"])
        self.bob_principal = str(self.bob.load_config("phoenix")["principal"])
        self.alice.trust("phoenix", self.bob_principal)
        self.bob.trust("phoenix", self.alice_principal)
        self.bob_ledger = ContextLedger("phoenix", self.root / "bob")
        self.checkpoint = committed_revision(self.bob_ledger)
        committed_blocker(self.bob_ledger)

    def tearDown(self) -> None:
        self.harness.close()
        self._directory.cleanup()
        if self._saved_home is None:
            os.environ.pop("BRAID_HOME", None)
        else:
            os.environ["BRAID_HOME"] = self._saved_home
        if self._saved_keychain is None:
            os.environ.pop("BRAID_DISABLE_KEYCHAIN", None)
        else:
            os.environ["BRAID_DISABLE_KEYCHAIN"] = self._saved_keychain

    def _ask(self, **overrides):
        payload = {
            "recipient": self.bob_principal,
            "purpose": "authentication handoff",
            "question": "Which authentication blockers changed?",
            "kinds": ["blocker"],
            "labels": ["backend"],
            "since_revision": str(self.checkpoint["id"]),
            "max_sensitivity": "internal",
            "max_claims": 5,
            "max_bytes": 50_000,
        }
        payload.update(overrides)
        queued = self.alice.queue_request("phoenix", **payload)
        self.alice.flush("phoenix")
        self.bob.sync("phoenix", "phoenix")
        return queued

    def _enable(self, **changes):
        settings = {
            "enabled": True,
            "allowed_peers": [self.alice_principal],
            "allowed_kinds": ["blocker"],
        }
        settings.update(changes)
        return self.bob.set_auto_policy("phoenix", settings)

    def test_default_policy_is_disabled_so_upgrades_answer_nothing(self) -> None:
        self._ask()
        result = self.bob.auto_respond("phoenix", "phoenix")
        self.assertFalse(result["enabled"])
        self.assertEqual(result["answered"], [])
        self.assertTrue(result["needs_human"])
        self.assertIn(
            "auto-respond is disabled for this project",
            result["referred"][0]["blockers"],
        )
        # The request is untouched and still answerable by a human.
        inbound = self._inbound()
        self.assertEqual(inbound["state"], "open")

    def _inbound(self):
        return next(
            item
            for item in self.bob.requests("phoenix")["requests"]
            if item["direction"] == "inbound"
        )

    def test_in_scope_request_is_answered_with_no_human(self) -> None:
        queued = self._ask()
        self._enable(allowed_peers=[self.alice_principal], allowed_kinds=["blocker"])

        result = self.bob.auto_respond("phoenix", "phoenix")
        self.assertEqual(len(result["answered"]), 1, result)
        self.assertFalse(result["needs_human"])
        self.assertTrue(result["answered"][0]["answered"])

        self.assertEqual(self._inbound()["state"], "response-queued")

        # The answer really travels: Alice receives it and it quarantines.
        self.bob.flush("phoenix")
        received = self.alice.sync("phoenix", "phoenix")
        self.assertEqual(len(received["responses"]), 1, received)
        self.assertEqual(received["responses"][0]["status"], "fulfilled")
        self.assertEqual(len(received["quarantined"]), 1)
        token = received["quarantined"][0]["quarantine_token"]
        review = ContextLedger("phoenix", self.root / "alice").review_import(token)
        self.assertEqual(review["claims"][0]["id"], "claim-auth-blocker")

        outbound = next(
            item
            for item in self.alice.requests("phoenix")["requests"]
            if item["direction"] == "outbound"
        )
        self.assertEqual(outbound["state"], "response-received")
        self.assertEqual(str(queued["request_id"]), outbound["request_id"])

    def test_dry_run_decides_without_answering(self) -> None:
        self._ask()
        self._enable(allowed_kinds=["blocker"])
        result = self.bob.auto_respond("phoenix", "phoenix", dry_run=True)
        self.assertEqual(len(result["answered"]), 1)
        self.assertFalse(result["answered"][0]["answered"])
        self.assertEqual(self._inbound()["state"], "open")

    def test_peer_outside_the_allowlist_is_referred(self) -> None:
        self._ask()
        self._enable(allowed_peers=["ed25519:" + "0" * 64], allowed_kinds=["blocker"])
        result = self.bob.auto_respond("phoenix", "phoenix")
        self.assertEqual(result["answered"], [])
        self.assertIn(
            "requester is not in the auto-respond peer allowlist",
            result["referred"][0]["blockers"],
        )
        self.assertEqual(self._inbound()["state"], "open")

    def test_kind_outside_policy_is_referred_as_scope_expansion(self) -> None:
        self._ask()
        self._enable(allowed_kinds=["decision"])
        result = self.bob.auto_respond("phoenix", "phoenix")
        self.assertEqual(result["answered"], [])
        self.assertTrue(
            any(
                "outside policy" in blocker
                for blocker in result["referred"][0]["blockers"]
            )
        )

    def test_rate_limit_stops_a_second_answer_in_the_same_hour(self) -> None:
        self._ask()
        self._enable(allowed_kinds=["blocker"], max_responses_per_hour=1)
        first = self.bob.auto_respond("phoenix", "phoenix")
        self.assertEqual(len(first["answered"]), 1)

        # A second, independent request in the same hour must not be answered.
        self._ask(question="Which blockers changed after the retry work?")
        second = self.bob.auto_respond("phoenix", "phoenix")
        self.assertEqual(second["answered"], [])
        self.assertIn("rate limit reached", second["referred"][0]["blockers"][0])

    def test_decisions_are_written_to_an_audit_log(self) -> None:
        self._ask()
        self._enable(allowed_kinds=["blocker"])
        self.bob.auto_respond("phoenix", "phoenix")
        path = self.bob.auto_policy_path("phoenix")
        self.assertTrue(path.exists())
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["decision"], "auto")
        self.assertTrue(record["answered"])
        self.assertEqual(record["requester"], self.alice_principal)
        # The log explains itself without carrying claim text.
        self.assertNotIn("callback allowlist", lines[0])

    def test_one_unanswerable_request_does_not_stop_the_others(self) -> None:
        self._ask()
        self._enable(allowed_kinds=["blocker"])
        # Corrupt one inbound record; the other must still be answered.
        broken = self.bob.exchange_state_path("phoenix", "inbound", "creq_" + "f" * 32)
        broken.parent.mkdir(parents=True, exist_ok=True)
        broken.write_text("{}", encoding="utf-8")
        result = self.bob.auto_respond("phoenix", "phoenix")
        self.assertEqual(len(result["answered"]), 1, result)

    def test_ledger_change_between_evaluation_and_answer_is_refused(self) -> None:
        """The authorization is bound to the payload, not to an earlier preview."""
        self._ask()
        self._enable(max_claims=1)

        # Simulate a commit landing between preview and send by widening what
        # the ledger would disclose only once respond() is already inside its
        # lock. The in-lock re-check must withdraw consent.
        original = connector.TeamConnector._plan_for
        calls = {"n": 0}

        def widening_plan(self, ledger, head, claim_ids):
            plan = original(self, ledger, head, claim_ids)
            calls["n"] += 1
            if calls["n"] > 1:  # the in-lock call, not the preview
                plan["claims"] = plan["claims"] * 3
            return plan

        with mock.patch.object(connector.TeamConnector, "_plan_for", widening_plan):
            result = self.bob.auto_respond("phoenix", "phoenix")

        self.assertEqual(result["answered"], [])
        self.assertTrue(
            any(
                "ledger changed between evaluation and answer" in blocker
                for blocker in result["referred"][0]["blockers"]
            ),
            result["referred"][0]["blockers"],
        )
        # Nothing was sent, and the request stays answerable by a human.
        self.assertEqual(self._inbound()["state"], "open")

    def test_authorization_reads_the_revision_being_disclosed_not_the_current_view(
        self,
    ) -> None:
        """`disclose` sends from `head`, so the decision must look at `head`.

        Reading the ledger's current view instead would let a commit landing
        after selection hide a claim from the policy while it is still sent
        from the earlier revision.
        """
        head = str(self.bob_ledger.status()["heads"][0])
        # A later commit retracts a claim, changing the CURRENT view only.
        committed_retraction(self.bob_ledger)
        self.assertNotEqual(str(self.bob_ledger.status()["heads"][0]), head)

        current_ids = {
            str(claim["id"]) for claim in self.bob_ledger.freshness()["active_claims"]
        }
        self.assertNotIn("claim-team-sync", current_ids)

        plan = self.bob._plan_for(self.bob_ledger, head, ["claim-team-sync"])
        self.assertEqual(
            [str(claim["id"]) for claim in plan["claims"]],
            ["claim-team-sync"],
            "authorization must still see the claim the disclosure will carry",
        )

    def test_answered_record_proves_what_was_sent(self) -> None:
        self._ask()
        self._enable()
        self.bob.auto_respond("phoenix", "phoenix")
        record = json.loads(
            self.bob.auto_policy_path("phoenix")
            .read_text(encoding="utf-8")
            .splitlines()[0]
        )
        self.assertEqual(record["claim_ids"], ["claim-auth-blocker"])
        self.assertTrue(record["source_revision"])

    def test_repeated_referrals_do_not_grow_the_log(self) -> None:
        self._ask()
        self._enable(allowed_kinds=["decision"])
        for _ in range(3):
            self.bob.auto_respond("phoenix", "phoenix")
        lines = [
            line
            for line in self.bob.auto_policy_path("phoenix")
            .read_text(encoding="utf-8")
            .splitlines()
            if line
        ]
        self.assertEqual(len(lines), 1, lines)

    def test_corrupt_audit_log_fails_closed(self) -> None:
        self._ask()
        self._enable()
        path = self.bob.auto_policy_path("phoenix")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not json\n", encoding="utf-8")
        with self.assertRaisesRegex(connector.ConnectorError, "audit log is corrupt"):
            self.bob.auto_respond("phoenix", "phoenix")

    def test_invalid_stored_policy_fails_the_project_closed(self) -> None:
        config = self.bob.load_config("phoenix")
        config["auto_respond"] = {"enabled": True, "bogus_field": 1}
        self.bob.save_config("phoenix", config)
        with self.assertRaisesRegex(connector.ConnectorError, "Auto-respond policy"):
            self.bob.auto_respond("phoenix", "phoenix")

    def test_policy_cannot_be_widened_to_restricted(self) -> None:
        with self.assertRaises(autopolicy.AutoPolicyError):
            self.bob.set_auto_policy("phoenix", {"max_sensitivity": "restricted"})
        # The rejected change was not persisted.
        self.assertEqual(self.bob.auto_policy("phoenix")["max_sensitivity"], "internal")

    def test_enabling_persists_across_connector_instances(self) -> None:
        self._enable(allowed_kinds=["blocker"], max_claims=7)
        fresh = connector.TeamConnector(self.root / "bob")
        policy = fresh.auto_policy("phoenix")
        self.assertTrue(policy["enabled"])
        self.assertEqual(policy["max_claims"], 7)


if __name__ == "__main__":
    unittest.main()
