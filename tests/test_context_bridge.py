from __future__ import annotations
import subprocess
import sys
import tempfile
import unittest
import json
import os
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


class ContextBridgeCliTests(unittest.TestCase):
    @staticmethod
    def cli_env(home: str) -> dict[str, str]:
        env = {**os.environ, "BRAID_HOME": home}
        vendor = Path.home() / ".braid" / "vendor"
        if vendor.is_dir():
            current = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = str(vendor) + (os.pathsep + current if current else "")
        return env

    def run_cli(self, home: str, *arguments: str, check: bool = True):
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "context_bridge.py"), *arguments],
            capture_output=True,
            text=True,
            env=self.cli_env(home),
            check=check,
        )

    def test_status_and_remote_path_rejection(self):
        with tempfile.TemporaryDirectory() as home:
            env = self.cli_env(home)
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "context_bridge.py"),
                    "--project",
                    "demo",
                    "status",
                ],
                capture_output=True,
                text=True,
                env=env,
                check=True,
            )
            self.assertEqual(json.loads(result.stdout)["project"], "demo")
            denied = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "context_bridge.py"),
                    "--project",
                    "demo",
                    "import",
                    "https://bad.example/x",
                ],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("local filesystem paths", denied.stderr)

    def test_extract_review_commit_flow_is_explicit_and_concise(self):
        with tempfile.TemporaryDirectory() as home:
            packet = Path(home) / "context.md"
            packet.write_text(
                "# Decisions\n- We decided to use SQLite for the prototype.\n",
                encoding="utf-8",
            )
            extracted = self.run_cli(
                home,
                "--project",
                "demo",
                "extract",
                "--markdown",
                str(packet),
                "--stage",
            )
            staged = json.loads(extracted.stdout)
            self.assertTrue(staged["requires_review"])
            stage_id = staged["stage_id"]
            denied = self.run_cli(
                home,
                "--project",
                "demo",
                "commit",
                "--author",
                "alice",
                "--stage-id",
                stage_id,
                check=False,
            )
            self.assertEqual(denied.returncode, 2)
            self.assertIn("not approved", denied.stderr)
            reviewed = self.run_cli(
                home,
                "--project",
                "demo",
                "review-staged",
                stage_id,
            )
            review = json.loads(reviewed.stdout)
            self.assertFalse(review["reviewed"])
            self.assertEqual(
                review["claims"][0]["statement"],
                "We decided to use SQLite for the prototype.",
            )
            approved = self.run_cli(
                home,
                "--project",
                "demo",
                "approve-staged",
                stage_id,
                "--review-digest",
                review["review_digest"],
            )
            self.assertTrue(json.loads(approved.stdout)["reviewed"])
            committed = self.run_cli(
                home,
                "--project",
                "demo",
                "commit",
                "--author",
                "alice",
                "--stage-id",
                stage_id,
            )
            output = json.loads(committed.stdout)
            self.assertEqual(output["claims"], 1)
            self.assertNotIn("governance", output)


if __name__ == "__main__":
    unittest.main()
