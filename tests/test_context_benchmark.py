from __future__ import annotations
import unittest
from benchmarks.context_quality.fixtures import holdout_fixtures, public_fixtures
from benchmarks.context_quality.oracle import reference_result, score
from benchmarks.context_quality.runner import run


class ContextBenchmarkTests(unittest.TestCase):
    def test_reference_contract_passes_every_public_gate(self) -> None:
        report = run("reference", holdout_seed=731)
        self.assertTrue(report["hard_gates_passed"])
        self.assertEqual(len(report["fixtures"]), len(public_fixtures()) + 12)

    def test_seeded_holdout_is_deterministic_and_changes_with_seed(self) -> None:
        self.assertEqual(holdout_fixtures(1), holdout_fixtures(1))
        self.assertNotEqual(holdout_fixtures(1), holdout_fixtures(2))

    def test_leak_provenance_and_unsafe_merge_fail_closed(self) -> None:
        fixture = next(
            x for x in public_fixtures() if x.name == "policy_secret_injection"
        )
        bad = reference_result(fixture)
        bad["recipient_pack"]["claims"].append(fixture.claims[1])
        bad["audit"] = []
        row = score(fixture, bad)
        self.assertFalse(row["passed"])
        self.assertFalse(row["gates"]["privacy"])
        provenance = next(x for x in public_fixtures() if x.name == "provenance")
        bad = reference_result(provenance)
        bad["claims"][0]["sources"] = []
        self.assertFalse(score(provenance, bad)["gates"]["provenance"])
        conflict = next(x for x in public_fixtures() if x.name == "merge_conflict")
        bad = reference_result(conflict)
        bad["merge"]["conflicts"][0]["resolution"] = "left-wins"
        self.assertFalse(score(conflict, bad)["gates"]["conflicts"])

    def test_raw_baseline_is_honestly_not_a_context_engine(self) -> None:
        self.assertFalse(run("raw")["hard_gates_passed"])


if __name__ == "__main__":
    unittest.main()
