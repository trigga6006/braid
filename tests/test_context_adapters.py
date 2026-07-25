from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import context_adapters as adapters  # noqa: E402
import context_bridge  # noqa: E402
import context_model  # noqa: E402
from context_store import ContextLedger  # noqa: E402


def claim() -> dict:
    claim = context_model.make_claim(
        "claim-db",
        "decision",
        "Use Postgres.",
        "database",
        [
            {
                "type": "test_result",
                "uri": "test://db",
                "digest": "sha256:" + "a" * 64,
                "observed_at": "2026-07-22T00:00:00Z",
            }
        ],
        confidence="confirmed",
    )
    return claim


def disclosure() -> dict:
    with tempfile.TemporaryDirectory() as directory:
        ledger = ContextLedger("a2a-sender", Path(directory))
        staged = ledger.stage([claim()])
        review = ledger.review_staged(staged["stage_id"])
        ledger.approve_staged(staged["stage_id"], review["review_digest"])
        revision = ledger.commit("alice")
        return ledger.disclose("project:a2a-receiver", revision["id"])["bundle"]


class ContextA2AAdapterTests(unittest.TestCase):
    @staticmethod
    def run_cli(*arguments: str, check: bool = True) -> SimpleNamespace:
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(sys, "argv", ["braid", *arguments]),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            returncode = context_bridge.main()
        result = SimpleNamespace(
            stdout=stdout.getvalue(),
            stderr=stderr.getvalue(),
            returncode=returncode,
        )
        if check and returncode:
            raise AssertionError(result.stderr)
        return result

    def test_round_trip_is_deterministic_and_does_not_make_a_task(self) -> None:
        exported = disclosure()
        artifact = adapters.bundle_to_a2a_artifact(exported)
        self.assertEqual(artifact["artifactId"], exported["export"]["revision"]["id"])
        self.assertNotIn("taskId", artifact)
        self.assertEqual(artifact["metadata"]["mimeType"], adapters.BUNDLE_MIME_TYPE)
        self.assertEqual(adapters.a2a_artifact_to_bundle(artifact), exported)
        self.assertEqual(adapters.bundle_to_a2a_artifact(exported), artifact)

    def test_rejects_wrong_mime_extra_parts_id_or_digest(self) -> None:
        artifact = adapters.bundle_to_a2a_artifact(disclosure())
        for mutate in (
            lambda item: item["metadata"].update({"mimeType": "text/plain"}),
            lambda item: item["parts"].append(copy.deepcopy(item["parts"][0])),
            lambda item: item.update({"artifactId": "another"}),
            lambda item: item["metadata"].update({"sha256": "0" * 64}),
        ):
            bad = copy.deepcopy(artifact)
            mutate(bad)
            with self.assertRaises(adapters.ContextAdapterError):
                adapters.a2a_artifact_to_bundle(bad)

    def test_rejects_invalid_or_tampered_revision_payload(self) -> None:
        artifact = adapters.bundle_to_a2a_artifact(disclosure())
        artifact["parts"][0]["data"]["export"]["revision"]["claims"][0]["statement"] = (
            "Unverified change."
        )
        with self.assertRaises(adapters.ContextAdapterError):
            adapters.a2a_artifact_to_bundle(artifact)

    def test_rejects_malformed_typed_a2a_envelope_fields(self) -> None:
        artifact = adapters.bundle_to_a2a_artifact(disclosure())
        for mutate in (
            lambda item: item.update({"name": {}}),
            lambda item: item.update({"description": []}),
            lambda item: item.update({"extensions": 42}),
            lambda item: item["metadata"].update({"untrusted": True}),
            lambda item: item["parts"][0]["metadata"].update({"untrusted": True}),
        ):
            bad = copy.deepcopy(artifact)
            mutate(bad)
            with self.assertRaises(adapters.ContextAdapterError):
                adapters.a2a_artifact_to_bundle(bad)

    def test_artifact_round_trip_enters_receiver_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sender = ContextLedger("a2a-source", root)
            receiver = ContextLedger("a2a-target", root)
            staged = sender.stage([claim()])
            review = sender.review_staged(staged["stage_id"])
            sender.approve_staged(staged["stage_id"], review["review_digest"])
            revision = sender.commit("alice")
            bundle = sender.disclose(receiver.principal, revision["id"])["bundle"]
            artifact = adapters.bundle_to_a2a_artifact(bundle)
            portable = adapters.a2a_artifact_to_bundle(artifact)
            path = root / "from-a2a.json"
            path.write_text(json.dumps(portable), encoding="utf-8")
            token = receiver.import_quarantine(path)
            reviewed = receiver.review_import(token)
            self.assertEqual(reviewed["claim_count"], 1)
            accepted = receiver.accept_import(token)
            self.assertEqual(accepted["claims"][0]["statement"], "Use Postgres.")

    def test_cli_a2a_round_trip_lands_in_quarantine_without_accepting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sender = ContextLedger("a2a-cli-source", root)
            receiver = ContextLedger("a2a-cli-target", root)
            staged = sender.stage([claim()])
            review = sender.review_staged(staged["stage_id"])
            sender.approve_staged(staged["stage_id"], review["review_digest"])
            revision = sender.commit("alice")
            artifact_path = root / "artifact.json"

            exported = self.run_cli(
                "--project",
                "a2a-cli-source",
                "--home",
                str(root),
                "a2a-export",
                revision["id"],
                "--recipient",
                receiver.principal,
                "--output",
                str(artifact_path),
            )
            export_result = json.loads(exported.stdout)
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
            self.assertEqual(export_result["artifactId"], artifact["artifactId"])
            self.assertEqual(export_result["digest"], artifact["metadata"]["sha256"])
            self.assertEqual(export_result["next_argv"][-2], "a2a-import")

            imported = self.run_cli(
                "--project",
                "a2a-cli-target",
                "--home",
                str(root),
                "a2a-import",
                str(artifact_path),
            )
            import_result = json.loads(imported.stdout)
            self.assertFalse(import_result["reviewed"])
            self.assertEqual(import_result["next_argv"][-2], "review-import")
            reviewed = receiver.review_import(import_result["quarantine_token"])
            self.assertEqual(reviewed["claim_count"], 1)
            status = receiver.status()
            self.assertEqual(status["heads"], [])
            self.assertEqual(status["sequence"], 0)
            self.assertEqual(status["quarantined"], 1)

    def test_cli_a2a_import_rejects_tampered_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = adapters.bundle_to_a2a_artifact(disclosure())
            artifact["parts"][0]["data"]["export"]["revision"]["claims"][0][
                "statement"
            ] = "Tampered."
            path = root / "tampered.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")

            result = self.run_cli(
                "--project",
                "a2a-cli-target",
                "--home",
                str(root),
                "a2a-import",
                str(path),
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("Invalid signed disclosure", result.stderr)
            self.assertEqual(
                ContextLedger("a2a-cli-target", root).status()["quarantined"], 0
            )

    def test_cli_a2a_import_sanitizes_control_characters_in_its_error(self) -> None:
        """An unverified artifact key is echoed back before any signature check.

        ``ContextAdapterError`` names the offending top-level field verbatim,
        so a key of ``ESC[2J`` would clear the reader's screen on the way to a
        rejection.  It must arrive as text.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = adapters.bundle_to_a2a_artifact(disclosure())
            artifact["\x1b[2J\rname"] = "forged"
            path = root / "control-key.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")

            result = self.run_cli(
                "--project",
                "a2a-cli-target",
                "--home",
                str(root),
                "a2a-import",
                str(path),
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("\x1b", result.stderr)
            self.assertNotIn("\r", result.stderr)
            self.assertIn("\\x1b[2J\\rname", result.stderr)
            self.assertEqual(
                result.stderr.strip().splitlines(), [result.stderr.strip()]
            )
            self.assertEqual(
                ContextLedger("a2a-cli-target", root).status()["quarantined"], 0
            )

    def test_cli_a2a_import_refuses_an_oversized_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "huge.json"
            # Capped BEFORE parsing, exactly like ``import``: the parser never
            # sees it, so there is nothing to exhaust memory with.
            path.write_text(
                json.dumps({"artifactId": "a" * 3_000_000}), encoding="utf-8"
            )

            result = self.run_cli(
                "--project",
                "a2a-cli-target",
                "--home",
                str(root),
                "a2a-import",
                str(path),
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("safety limit", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_cli_a2a_import_refuses_a_deeply_nested_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "nested.json"
            depth = 5_000
            path.write_text(
                '{"artifactId":' + "[" * depth + "]" * depth + "}", encoding="utf-8"
            )

            result = self.run_cli(
                "--project",
                "a2a-cli-target",
                "--home",
                str(root),
                "a2a-import",
                str(path),
                check=False,
            )
            # Fails closed as a clean error, not as an uncaught RecursionError.
            self.assertEqual(result.returncode, 2)
            self.assertIn("Unsafe import", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_cli_a2a_import_refuses_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "duplicate.json"
            # Last-wins would let a second copy of a field decide what is
            # imported after the first copy passed inspection.
            path.write_text(
                '{"artifactId": "benign", "artifactId": "swapped"}', encoding="utf-8"
            )

            result = self.run_cli(
                "--project",
                "a2a-cli-target",
                "--home",
                str(root),
                "a2a-import",
                str(path),
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("duplicate JSON key", result.stderr)

    def test_cli_a2a_import_rejects_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = adapters.bundle_to_a2a_artifact(disclosure())
            artifact["metadata"]["sha256"] = "0" * 64
            path = root / "digest-mismatch.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")

            result = self.run_cli(
                "--project",
                "a2a-cli-target",
                "--home",
                str(root),
                "a2a-import",
                str(path),
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("digest does not match", result.stderr)
            self.assertEqual(
                ContextLedger("a2a-cli-target", root).status()["quarantined"], 0
            )
