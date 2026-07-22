from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import context_adapters as adapters  # noqa: E402
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
