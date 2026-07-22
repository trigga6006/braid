from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import context_mcp  # noqa: E402
import context_model  # noqa: E402
from context_store import ContextLedger  # noqa: E402


class FakeLedger:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def dispatch(self, operation: str, arguments: dict) -> dict:
        self.calls.append((operation, arguments))
        return {"operation": operation, "arguments": arguments}

    def read_resource(self, name: str) -> dict:
        return {"resource": name}


class ContextMcpTests(unittest.TestCase):
    @staticmethod
    def ready_session(ledger):
        state = {"phase": "new"}
        initialized = context_mcp.handle_request(
            ledger,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": context_mcp.PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "tests", "version": "1"},
                },
            },
            state,
        )
        context_mcp.handle_request(
            ledger,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            state,
        )
        return state, initialized

    def test_initialize_lists_tools_and_resources(self) -> None:
        ledger = FakeLedger()
        state, initialized = self.ready_session(ledger)
        self.assertEqual(initialized["result"]["serverInfo"]["name"], "braid-context")
        tools = context_mcp.handle_request(
            ledger, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, state
        )
        self.assertIn(
            "braid_disclose", [item["name"] for item in tools["result"]["tools"]]
        )
        resources = context_mcp.handle_request(
            ledger, {"jsonrpc": "2.0", "id": 3, "method": "resources/list"}, state
        )
        self.assertIn(
            "braid://ledger", [item["uri"] for item in resources["result"]["resources"]]
        )
        definitions = tools["result"]["tools"]
        self.assertTrue(
            all(
                item["inputSchema"]["additionalProperties"] is False
                for item in definitions
            )
        )
        self.assertIn("braid_accept_import", [item["name"] for item in definitions])

    def test_tool_and_resource_delegate_to_the_same_ledger(self) -> None:
        ledger = FakeLedger()
        state, _ = self.ready_session(ledger)
        result = context_mcp.handle_request(
            ledger,
            {
                "jsonrpc": "2.0",
                "id": "a",
                "method": "tools/call",
                "params": {
                    "name": "braid_revoke",
                    "arguments": {"claim_id": "claim-db", "reason": "withdrawn"},
                },
            },
            state,
        )
        self.assertEqual(result["result"]["structuredContent"]["operation"], "revoke")
        self.assertEqual(
            ledger.calls,
            [("revoke", {"claim_id": "claim-db", "reason": "withdrawn"})],
        )
        resource = context_mcp.handle_request(
            ledger,
            {
                "jsonrpc": "2.0",
                "id": "b",
                "method": "resources/read",
                "params": {"uri": "braid://ledger"},
            },
            state,
        )
        self.assertEqual(
            json.loads(resource["result"]["contents"][0]["text"]),
            {"resource": "ledger"},
        )

    def test_stdio_parse_error_notification_and_unknown_tool(self) -> None:
        ledger, output = FakeLedger(), io.StringIO()
        context_mcp.serve(
            ledger,
            io.StringIO(
                "not json\n"
                + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
                + "\n"
            ),
            output,
        )
        replies = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(replies), 1)
        self.assertEqual(replies[0]["error"]["code"], -32700)
        bad = context_mcp.handle_request(
            ledger,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "send_message"},
            },
            self.ready_session(ledger)[0],
        )
        self.assertEqual(bad["error"]["code"], -32602)

    def test_stdio_rejects_duplicate_keys_and_oversized_lines(self) -> None:
        output = io.StringIO()
        duplicate = '{"jsonrpc":"2.0","id":1,"id":2,"method":"initialize"}\n'
        oversized = "{" + "x" * context_mcp.MAX_REQUEST_CHARS + "}\n"
        context_mcp.serve(FakeLedger(), io.StringIO(duplicate + oversized), output)
        replies = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([item["error"]["code"] for item in replies], [-32700, -32700])

    def test_lifecycle_notifications_and_ids_are_enforced(self) -> None:
        ledger = FakeLedger()
        state = {"phase": "new"}
        before = context_mcp.handle_request(
            ledger,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            state,
        )
        self.assertEqual(before["error"]["code"], -32002)
        invalid_id = context_mcp.handle_request(
            ledger,
            {"jsonrpc": "2.0", "id": {"bad": 1}, "method": "tools/list"},
            state,
        )
        self.assertEqual(invalid_id["error"]["code"], -32600)
        state, _ = self.ready_session(ledger)
        invalid_notification = context_mcp.handle_request(
            ledger,
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "notifications/initialized",
            },
            state,
        )
        self.assertEqual(invalid_notification["error"]["code"], -32600)

    def test_actual_ledger_adapter_remains_a_thin_state_adapter(self) -> None:
        claim = context_model.make_claim(
            "claim-one",
            "fact",
            "Tests are green.",
            "tests",
            [
                {
                    "type": "test_result",
                    "uri": "test://suite",
                    "observed_at": "2026-07-22T00:00:00Z",
                }
            ],
        )
        with tempfile.TemporaryDirectory() as directory:
            adapter = context_mcp.ContextLedgerMcpAdapter(
                ContextLedger("mcp-test", Path(directory))
            )
            staged = context_mcp.call_ledger_operation(
                adapter,
                "stage",
                {"claims": [claim], "message": "stage"},
            )
            self.assertEqual(len(staged["claims"]), 1)
            review = context_mcp.call_ledger_operation(
                adapter, "review_staged", {"stage_id": staged["stage_id"]}
            )
            context_mcp.call_ledger_operation(
                adapter,
                "approve_staged",
                {
                    "stage_id": staged["stage_id"],
                    "review_digest": review["review_digest"],
                },
            )
            committed = context_mcp.call_ledger_operation(
                adapter, "commit", {"author": "alice"}
            )
            packed = context_mcp.call_ledger_operation(
                adapter, "pack", {"revision_id": committed["id"]}
            )
            self.assertEqual(packed["id"], committed["id"])
            self.assertTrue(
                context_mcp.call_ledger_operation(adapter, "verify", {})["audit_valid"]
            )

    def test_mcp_completes_quarantine_review_accept_lifecycle(self) -> None:
        claim = context_model.make_claim(
            "claim-portable",
            "fact",
            "The MCP lifecycle uses the canonical ledger.",
            "mcp-lifecycle",
            [
                {
                    "type": "test_result",
                    "uri": "test://mcp-lifecycle",
                    "observed_at": "2026-07-22T00:00:00Z",
                }
            ],
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sender = ContextLedger("mcp-source", root)
            staged = sender.stage([claim])
            review = sender.review_staged(staged["stage_id"])
            sender.approve_staged(staged["stage_id"], review["review_digest"])
            revision = sender.commit("alice")
            path = root / "mcp-disclosure.json"
            adapter = context_mcp.ContextLedgerMcpAdapter(
                ContextLedger("mcp-target", root)
            )
            sender.export(revision["id"], path, recipient=adapter.ledger.principal)
            imported = context_mcp.call_ledger_operation(
                adapter, "import", {"source": str(path)}
            )
            token = imported["quarantine_token"]
            with self.assertRaises(PermissionError):
                context_mcp.call_ledger_operation(
                    adapter, "accept_import", {"token": token}
                )
            review = context_mcp.call_ledger_operation(
                adapter, "review_import", {"token": token}
            )
            self.assertEqual(review["claim_count"], 1)
            accepted = context_mcp.call_ledger_operation(
                adapter, "accept_import", {"token": token}
            )
            self.assertEqual(accepted["claims"][0]["id"], "claim-portable")

    def test_unknown_tool_arguments_are_rejected(self) -> None:
        with self.assertRaisesRegex(context_mcp.McpProtocolError, "Unknown"):
            context_mcp.call_ledger_operation(
                FakeLedger(), "ledger", {"unexpected": True}
            )

    def test_tool_argument_types_are_enforced_recursively(self) -> None:
        invalid = (
            ("accept_import", {"token": "abc", "allow_sensitive": "yes"}),
            ("reconcile", {"local": [1], "remote": ["r-2"]}),
            ("stage", {"claims": ["not-an-object"]}),
        )
        for operation, arguments in invalid:
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(context_mcp.McpProtocolError, "must be"):
                    context_mcp.call_ledger_operation(
                        FakeLedger(), operation, arguments
                    )
