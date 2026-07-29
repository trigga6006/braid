"""The ``next_argv`` hint has to run verbatim through the documented front door.

Every command below hands back an array that the skill instructs an agent to
execute as-is.  These tests execute exactly that array -- nothing is rewritten,
reordered, or re-derived -- so an array that names the wrong group, or no group
at all, fails here instead of in an agent's terminal.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import braid_cli  # noqa: E402


CHECKPOINT = "# Decisions\n- We decided to use SQLite for the prototype.\n"


class NextArgvRunsThroughTheFrontDoorTests(unittest.TestCase):
    def follow(self, argv: list[str]) -> dict:
        """Run one emitted array through ``braid`` and return its JSON output."""
        self.assertEqual(argv[0], "braid", f"argv[0] is not the front door: {argv}")
        self.assertIn(
            argv[1],
            braid_cli.GROUPS,
            f"argv[1] is not a group the front door can resolve: {argv}",
        )
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = braid_cli.main(argv[1:])
        self.assertEqual(code, 0, f"exit {code} from: {' '.join(argv)}")
        return json.loads(stream.getvalue())

    @staticmethod
    def checkpoint(root: Path) -> Path:
        path = root / "checkpoint.md"
        path.write_text(CHECKPOINT, encoding="utf-8")
        return path

    def test_extract_review_approve_commit_chain_is_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = ["braid", "ledger", "--project", "demo", "--home", str(root)]

            staged = self.follow(
                [*base, "extract", "--markdown", str(self.checkpoint(root)), "--stage"]
            )
            reviewed = self.follow(staged["next_argv"])
            self.assertFalse(reviewed["reviewed"])
            approved = self.follow(reviewed["next_argv"])
            self.assertTrue(approved["reviewed"])
            committed = self.follow(approved["next_argv"])
            self.assertTrue(committed["revision"].startswith("r-"))
            # commit points at the minimization preview.  Its recipient is a
            # placeholder for the agent to fill in, but the array still runs.
            self.assertTrue(self.follow(committed["next_argv"])["requires_review"])

    def test_stage_next_argv_is_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = ["braid", "ledger", "--project", "demo", "--home", str(root)]
            claims = root / "claims.json"

            self.follow(
                [
                    *base,
                    "extract",
                    "--markdown",
                    str(self.checkpoint(root)),
                    "--output",
                    str(claims),
                ]
            )
            staged = self.follow([*base, "stage", "--claims", str(claims)])
            self.assertEqual(
                self.follow(staged["next_argv"])["stage_id"], staged["stage_id"]
            )

    def test_import_review_accept_chain_is_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = ["braid", "ledger", "--project", "source", "--home", str(root)]
            target = ["braid", "ledger", "--project", "target", "--home", str(root)]

            staged = self.follow(
                [
                    *source,
                    "extract",
                    "--markdown",
                    str(self.checkpoint(root)),
                    "--stage",
                ]
            )
            approved = self.follow(self.follow(staged["next_argv"])["next_argv"])
            revision = self.follow(approved["next_argv"])["revision"]
            recipient = self.follow([*target, "status"])["principal"]

            bundle = root / "bundle.json"
            self.follow(
                [
                    *source,
                    "export",
                    revision,
                    "--recipient",
                    recipient,
                    "--output",
                    str(bundle),
                ]
            )
            imported = self.follow([*target, "import", str(bundle)])
            self.assertEqual(self.follow(imported["next_argv"])["claim_count"], 1)
            accepted = self.follow([*target, "accept", imported["quarantine_token"]])
            freshness = self.follow(accepted["next_argv"])
            self.assertEqual(len(freshness["active_claims"]), 1)

    def test_a2a_export_and_import_next_argv_are_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = ["braid", "ledger", "--project", "demo", "--home", str(root)]

            staged = self.follow(
                [*base, "extract", "--markdown", str(self.checkpoint(root)), "--stage"]
            )
            approved = self.follow(self.follow(staged["next_argv"])["next_argv"])
            revision = self.follow(approved["next_argv"])["revision"]
            recipient = self.follow([*base, "status"])["principal"]

            exported = self.follow(
                [
                    *base,
                    "a2a-export",
                    revision,
                    "--recipient",
                    recipient,
                    "--output",
                    str(root / "artifact.json"),
                ]
            )
            imported = self.follow(exported["next_argv"])
            self.assertFalse(imported["reviewed"])
            self.assertEqual(self.follow(imported["next_argv"])["claim_count"], 1)


if __name__ == "__main__":
    unittest.main()
