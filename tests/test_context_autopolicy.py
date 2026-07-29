from __future__ import annotations

from pathlib import Path
import sys
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import context_autopolicy as autopolicy  # noqa: E402


PERMISSIVE = {
    "enabled": True,
    "max_sensitivity": "confidential",
    "allowed_peers": ["ed25519:peer"],
    "allowed_kinds": sorted(
        {
            "fact",
            "decision",
            "constraint",
            "hypothesis",
            "question",
            "action",
            "blocker",
            "disagreement",
        }
    ),
    "denied_labels": [],
    "max_claims": 200,
    "max_bytes": 500_000,
    "max_responses_per_hour": 240,
}

CLEAN_LEDGER = {"heads": ["r-1"], "open_conflicts": []}


def _claim(**overrides):
    claim = {
        "id": "c-1",
        "kind": "decision",
        "sensitivity": "internal",
        "labels": ["auth"],
        "statement": "Auth rollout uses short-lived tokens.",
        "provenance": [{"type": "human_statement"}],
    }
    claim.update(overrides)
    return claim


def _request(**overrides):
    """A Context Pull Request in the shape `context_exchange` actually signs."""
    selectors = {
        "kinds": overrides.pop("kinds", ["decision"]),
        "semantic_keys": overrides.pop("semantic_keys", []),
        "labels": overrides.pop("labels", []),
    }
    request = {
        "sender": "ed25519:peer",
        "request_id": "cpr-1",
        "selectors": selectors,
        "max_sensitivity": "internal",
        "purpose": "auth rollout status",
        "question": "",
    }
    request.update(overrides)
    return request


def _plan(claims=None, excluded=None, used_bytes=500):
    return {
        "claims": [_claim()] if claims is None else claims,
        "excluded": excluded or [],
        "budget": {"used_bytes": used_bytes},
    }


def _decide(request=None, policy=None, plan=None, ledger=None, **kwargs):
    return autopolicy.evaluate(
        request or _request(),
        policy or dict(PERMISSIVE),
        plan or _plan(),
        ledger_status=CLEAN_LEDGER if ledger is None else ledger,
        **kwargs,
    )


class PolicyValidationTests(unittest.TestCase):
    def test_absent_policy_is_disabled_by_default(self) -> None:
        self.assertFalse(autopolicy.load_policy(None)["enabled"])

    def test_unknown_field_is_rejected_rather_than_ignored(self) -> None:
        # A typo must not silently widen automation.
        with self.assertRaises(autopolicy.AutoPolicyError) as caught:
            autopolicy.load_policy({"enabled": True, "max_sensitivty": "restricted"})
        self.assertIn("max_sensitivty", str(caught.exception))

    def test_restricted_ceiling_is_refused_outright(self) -> None:
        with self.assertRaises(autopolicy.AutoPolicyError) as caught:
            autopolicy.load_policy({"max_sensitivity": "restricted"})
        self.assertIn("always requires review", str(caught.exception))

    def test_unsupported_version_is_refused(self) -> None:
        with self.assertRaises(autopolicy.AutoPolicyError):
            autopolicy.load_policy({"version": 99})

    def test_unknown_claim_kind_is_refused(self) -> None:
        with self.assertRaises(autopolicy.AutoPolicyError) as caught:
            autopolicy.load_policy({"allowed_kinds": ["decision", "gossip"]})
        self.assertIn("gossip", str(caught.exception))

    def test_numeric_bounds_are_enforced(self) -> None:
        for field, value in (
            ("max_claims", 0),
            ("max_claims", 10_000),
            ("max_bytes", 10),
            ("max_responses_per_hour", 0),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(autopolicy.AutoPolicyError):
                    autopolicy.load_policy({field: value})

    def test_booleans_are_not_accepted_as_integers(self) -> None:
        with self.assertRaises(autopolicy.AutoPolicyError):
            autopolicy.load_policy({"max_claims": True})


class HardStopTests(unittest.TestCase):
    """These refer regardless of how permissive the policy is."""

    def assert_refers(self, decision, fragment: str) -> None:
        self.assertEqual(decision["decision"], "refer")
        self.assertTrue(
            any(fragment in blocker for blocker in decision["blockers"]),
            f"{fragment!r} not in {decision['blockers']}",
        )

    def test_divergent_heads_refer(self) -> None:
        self.assert_refers(_decide(ledger={"heads": ["r-1", "r-2"]}), "divergent heads")

    def test_open_conflicts_refer(self) -> None:
        self.assert_refers(
            _decide(ledger={"heads": ["r-1"], "open_conflicts": ["c-9"]}),
            "unresolved semantic conflicts",
        )

    def test_request_for_restricted_context_refers(self) -> None:
        self.assert_refers(
            _decide(request=_request(max_sensitivity="restricted")),
            "restricted context",
        )

    def test_restricted_claim_in_plan_refers(self) -> None:
        self.assert_refers(
            _decide(plan=_plan([_claim(sensitivity="restricted")])),
            "restricted context",
        )

    def test_secret_scanner_finding_refers(self) -> None:
        self.assert_refers(
            _decide(
                plan=_plan(
                    excluded=[
                        {
                            "claim_id": "c-9",
                            "reason": "secret scanner finding requires explicit redaction",
                        }
                    ]
                )
            ),
            "secret scanner",
        )

    def test_raw_transcript_provenance_refers(self) -> None:
        self.assert_refers(
            _decide(plan=_plan([_claim(provenance=[{"type": "transcript_excerpt"}])])),
            "raw session transcript",
        )

    def test_malformed_claim_refers(self) -> None:
        self.assert_refers(_decide(plan=_plan(["not-a-claim"])), "malformed claim")


class PolicyGateTests(unittest.TestCase):
    def test_clean_in_scope_request_is_authorized(self) -> None:
        decision = _decide()
        self.assertEqual(decision["decision"], "auto")
        self.assertEqual(decision["blockers"], [])
        self.assertEqual(decision["correlation_id"], "cpr-1")

    def test_disabled_policy_refers(self) -> None:
        policy = dict(PERMISSIVE, enabled=False)
        decision = _decide(policy=policy)
        self.assertEqual(decision["decision"], "refer")
        self.assertIn("auto-respond is disabled for this project", decision["blockers"])

    def test_enabling_without_a_peer_allowlist_is_refused(self) -> None:
        # An empty list must not silently mean "every trusted peer".
        with self.assertRaises(autopolicy.AutoPolicyError) as caught:
            autopolicy.load_policy({"enabled": True, "allowed_peers": []})
        self.assertIn("explicit allowed_peers", str(caught.exception))

    def test_enabling_without_allowed_kinds_is_refused(self) -> None:
        with self.assertRaises(autopolicy.AutoPolicyError):
            autopolicy.load_policy(
                {"enabled": True, "allowed_peers": ["ed25519:p"], "allowed_kinds": []}
            )

    def test_peer_outside_allowlist_refers(self) -> None:
        policy = dict(PERMISSIVE, allowed_peers=["ed25519:other"])
        decision = _decide(policy=policy)
        self.assertEqual(decision["decision"], "refer")
        self.assertIn(
            "requester is not in the auto-respond peer allowlist", decision["blockers"]
        )

    def test_missing_requester_refers(self) -> None:
        request = _request()
        del request["sender"]
        decision = _decide(request=request)
        self.assertEqual(decision["decision"], "refer")
        self.assertIn("no identifiable requester", decision["blockers"][0])

    def test_request_over_policy_ceiling_refers(self) -> None:
        policy = dict(PERMISSIVE, max_sensitivity="internal")
        decision = _decide(
            request=_request(max_sensitivity="confidential"), policy=policy
        )
        self.assertEqual(decision["decision"], "refer")
        self.assertIn(
            "request exceeds the policy sensitivity ceiling", decision["blockers"]
        )

    def test_kind_outside_policy_is_scope_expansion(self) -> None:
        policy = dict(PERMISSIVE, allowed_kinds=["decision"])
        decision = _decide(
            request=_request(kinds=["decision", "hypothesis"]), policy=policy
        )
        self.assertEqual(decision["decision"], "refer")
        self.assertTrue(
            any("outside policy" in blocker for blocker in decision["blockers"])
        )

    def test_denied_label_refers(self) -> None:
        policy = dict(PERMISSIVE, denied_labels=["untrusted-source"])
        plan = _plan([_claim(labels=["auth", "untrusted-source"])])
        decision = _decide(policy=policy, plan=plan)
        self.assertEqual(decision["decision"], "refer")
        self.assertTrue(
            any("denied label" in blocker for blocker in decision["blockers"])
        )

    def test_claim_and_byte_ceilings_refer(self) -> None:
        policy = dict(PERMISSIVE, max_claims=1, max_bytes=1_024)
        plan = _plan(
            [_claim(id="c-1"), _claim(id="c-2")],
            used_bytes=5_000,
        )
        decision = _decide(policy=policy, plan=plan)
        self.assertEqual(decision["decision"], "refer")
        self.assertIn(
            "disclosure plan exceeds the policy claim ceiling", decision["blockers"]
        )
        self.assertIn(
            "disclosure plan exceeds the policy byte ceiling", decision["blockers"]
        )

    def test_rate_limit_refers_and_counts_only_the_last_hour(self) -> None:
        policy = dict(PERMISSIVE, max_responses_per_hour=2)
        now = "2026-07-01T12:00:00Z"
        recent = ["2026-07-01T11:30:00Z", "2026-07-01T11:45:00Z"]
        decision = _decide(policy=policy, recent_responses=recent, now=now)
        self.assertEqual(decision["decision"], "refer")
        self.assertIn("rate limit reached", decision["blockers"][0])
        self.assertEqual(decision["responses_last_hour"], 2)

        stale = ["2026-07-01T09:00:00Z", "2026-07-01T10:00:00Z"]
        allowed = _decide(policy=policy, recent_responses=stale, now=now)
        self.assertEqual(allowed["decision"], "auto")
        self.assertEqual(allowed["responses_last_hour"], 0)

    def test_unparsable_timestamps_count_against_the_rate_limit(self) -> None:
        policy = dict(PERMISSIVE, max_responses_per_hour=1)
        decision = _decide(
            policy=policy,
            recent_responses=["not-a-time"],
            now="2026-07-01T12:00:00Z",
        )
        # A record that exists but cannot be dated is still evidence an answer
        # was sent; dropping it would widen the budget.
        self.assertEqual(decision["responses_last_hour"], 1)
        self.assertEqual(decision["decision"], "refer")


class RelevanceTests(unittest.TestCase):
    def test_claim_the_request_did_not_ask_for_refers(self) -> None:
        plan = _plan(
            [
                _claim(),
                _claim(
                    id="c-99",
                    kind="fact",
                    labels=["payroll"],
                    statement="Payroll vendor renews in March.",
                ),
            ]
        )
        decision = _decide(plan=plan)
        self.assertEqual(decision["decision"], "refer")
        self.assertTrue(
            any("did not ask for" in blocker for blocker in decision["blockers"])
        )
        self.assertIn("c-99", decision["blockers"][0])

    def test_label_selector_keeps_a_claim_in_scope(self) -> None:
        request = _request(kinds=[], labels=["payroll"], purpose="")
        plan = _plan([_claim(id="c-99", kind="fact", labels=["payroll"])])
        self.assertEqual(_decide(request=request, plan=plan)["decision"], "auto")

    def test_purpose_overlap_alone_does_not_authorize(self) -> None:
        # Lexical overlap is not relevance: a purpose of "the" shares a word
        # with nearly any statement, so only structural selectors count.
        request = _request(kinds=[], labels=[], purpose="payroll renewal")
        plan = _plan(
            [
                _claim(
                    id="c-99",
                    kind="fact",
                    labels=[],
                    statement="Payroll vendor renews in March.",
                )
            ]
        )
        self.assertEqual(_decide(request=request, plan=plan)["decision"], "refer")

    def test_generic_purpose_word_cannot_smuggle_an_unrelated_claim(self) -> None:
        request = _request(kinds=[], labels=["payroll"], purpose="the")
        plan = _plan(
            [
                _claim(
                    id="c-99",
                    kind="fact",
                    labels=["unrelated"],
                    statement="The vendor renews in March.",
                )
            ]
        )
        decision = _decide(request=request, plan=plan)
        self.assertEqual(decision["decision"], "refer")
        self.assertTrue(
            any("did not ask for" in blocker for blocker in decision["blockers"])
        )

    def test_disclosed_kind_outside_policy_refers_even_with_no_requested_kinds(
        self,
    ) -> None:
        # The request declares no kinds and selects by label, so checking only
        # the request's kinds would authorize a kind the policy never allowed.
        policy = dict(PERMISSIVE, allowed_kinds=["decision"])
        request = _request(kinds=[], labels=["payroll"])
        plan = _plan([_claim(id="c-99", kind="fact", labels=["payroll"])])
        decision = _decide(request=request, policy=policy, plan=plan)
        self.assertEqual(decision["decision"], "refer")
        self.assertTrue(
            any(
                "disclosure plan contains kinds outside policy" in blocker
                for blocker in decision["blockers"]
            )
        )

    def test_request_with_no_selectors_at_all_refers(self) -> None:
        # Nothing bounds what such a request would receive, so it is a scope
        # expansion by construction.
        request = _request(kinds=[], labels=[], purpose="", question="")
        decision = _decide(request=request)
        self.assertEqual(decision["decision"], "refer")

    def test_empty_plan_is_authorized(self) -> None:
        # Answering "nothing matched" is in scope and leaks nothing.
        decision = _decide(plan=_plan([], used_bytes=2))
        self.assertEqual(decision["decision"], "auto")
        self.assertEqual(decision["claims"], 0)


class AuditRecordTests(unittest.TestCase):
    def test_record_carries_everything_needed_to_explain_itself(self) -> None:
        decision = _decide()
        for field in (
            "decision",
            "blockers",
            "requester",
            "correlation_id",
            "claims",
            "used_bytes",
            "responses_last_hour",
            "policy",
            "evaluated_at",
        ):
            self.assertIn(field, decision)
        self.assertEqual(decision["policy"]["max_claims"], PERMISSIVE["max_claims"])

    def test_all_blockers_are_reported_not_just_the_first(self) -> None:
        policy = dict(PERMISSIVE, enabled=False, allowed_peers=["ed25519:other"])
        decision = _decide(policy=policy, ledger={"heads": ["r-1", "r-2"]})
        self.assertGreaterEqual(len(decision["blockers"]), 3)


if __name__ == "__main__":
    unittest.main()
