"""Standard-library MCP stdio adapter over the canonical Braid ledger.

The injected ledger remains the only state model.  This server adds no tasks,
messages, persistence, policies, or alternate context representation.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
import sys
from typing import Any, TextIO

from context_security import SecurityError, strict_json_loads


SERVER_NAME, SERVER_VERSION, PROTOCOL_VERSION = "braid-context", "0.4.0", "2025-06-18"
MAX_REQUEST_CHARS = 1_000_000
OPERATIONS = (
    "stage",
    "review_staged",
    "approve_staged",
    "diff",
    "commit",
    "plan",
    "pack",
    "disclose",
    "import",
    "review_import",
    "accept_import",
    "reconcile",
    "resolve",
    "freshness",
    "ledger",
    "revoke",
    "verify",
)
RESOURCES = {
    "braid://ledger": "ledger",
    "braid://conflicts": "conflicts",
    "braid://freshness": "freshness",
}


class McpProtocolError(ValueError):
    pass


class ContextLedgerMcpAdapter:
    """Operation adapter for ``ContextLedger``; it never stores context itself."""

    def __init__(self, ledger: Any) -> None:
        self.ledger = ledger

    def dispatch(self, operation: str, arguments: dict[str, Any]) -> Any:
        if operation == "stage":
            return self.ledger.stage(
                arguments["claims"],
                arguments.get("message", ""),
                arguments.get("reconciliation_token"),
            )
        if operation == "review_staged":
            return self.ledger.review_staged(arguments["stage_id"])
        if operation == "approve_staged":
            return self.ledger.approve_staged(
                arguments["stage_id"], arguments["review_digest"]
            )
        if operation == "commit":
            return self.ledger.commit(
                arguments["author"],
                arguments.get("governance"),
                arguments.get("message"),
                arguments.get("stage_id"),
            )
        if operation == "diff":
            return self.ledger.diff(arguments["before"], arguments["after"])
        if operation == "pack":
            return self.ledger.show(arguments["revision_id"])
        if operation == "plan":
            return self.ledger.plan(
                arguments["recipient_profile"], arguments.get("claim_ids")
            )
        if operation == "disclose":
            return self.ledger.disclose(
                arguments["recipient"],
                arguments["revision_id"],
                arguments.get("claim_ids"),
                arguments.get("purpose", "Context reconciliation"),
                arguments.get("max_sensitivity", "internal"),
            )
        if operation == "import":
            return {
                "quarantine_token": self.ledger.import_quarantine(
                    Path(arguments["source"])
                )
            }
        if operation == "review_import":
            return self.ledger.review_import(arguments["token"])
        if operation == "accept_import":
            return self.ledger.accept_import(
                arguments["token"],
                allow_sensitive=arguments.get("allow_sensitive", False),
            )
        if operation == "resolve":
            return self.ledger.stage(
                arguments["claims"],
                "resolve: " + arguments["message"],
                arguments.get("reconciliation_token"),
            )
        if operation == "revoke":
            self.ledger.revoke(arguments["claim_id"], arguments["reason"])
            return {"claim_id": arguments["claim_id"], "revoked": True}
        if operation == "ledger":
            return self.ledger.status()
        if operation == "verify":
            return {"audit_valid": self.ledger.verify_audit()}
        if operation == "freshness":
            return self.ledger.freshness(arguments.get("now"))
        if operation == "reconcile":
            return self.ledger.prepare_reconciliation(
                arguments["local"], arguments["remote"]
            )
        raise McpProtocolError(
            f"Canonical ContextLedger does not expose `{operation}`."
        )

    def read_resource(self, name: str) -> Any:
        if name == "ledger":
            return self.ledger.status()
        if name == "freshness":
            return self.dispatch("freshness", {})
        if name == "conflicts":
            return self.ledger.conflicts()
        raise McpProtocolError(f"Unknown Braid resource: {name}")


def _schema(
    properties: dict[str, dict[str, Any]] | None = None,
    required: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties or {},
        "required": list(required),
        "additionalProperties": False,
    }


_STRING = {"type": "string"}
_STRINGS = {"type": "array", "items": _STRING}
TOOL_SCHEMAS = {
    "stage": _schema(
        {
            "claims": {"type": "array", "items": {"type": "object"}},
            "message": _STRING,
            "reconciliation_token": _STRING,
        },
        ("claims",),
    ),
    "review_staged": _schema({"stage_id": _STRING}, ("stage_id",)),
    "approve_staged": _schema(
        {"stage_id": _STRING, "review_digest": _STRING},
        ("stage_id", "review_digest"),
    ),
    "commit": _schema(
        {
            "author": _STRING,
            "governance": {"type": "object"},
            "message": _STRING,
            "stage_id": _STRING,
        },
        ("author",),
    ),
    "diff": _schema({"before": _STRING, "after": _STRING}, ("before", "after")),
    "pack": _schema({"revision_id": _STRING}, ("revision_id",)),
    "plan": _schema(
        {"recipient_profile": {"type": "object"}, "claim_ids": _STRINGS},
        ("recipient_profile",),
    ),
    "disclose": _schema(
        {
            "recipient": _STRING,
            "revision_id": _STRING,
            "claim_ids": _STRINGS,
            "purpose": _STRING,
            "max_sensitivity": _STRING,
        },
        ("recipient", "revision_id"),
    ),
    "import": _schema({"source": _STRING}, ("source",)),
    "review_import": _schema({"token": _STRING}, ("token",)),
    "accept_import": _schema(
        {"token": _STRING, "allow_sensitive": {"type": "boolean"}}, ("token",)
    ),
    "reconcile": _schema({"local": _STRINGS, "remote": _STRINGS}, ("local", "remote")),
    "resolve": _schema(
        {
            "claims": {"type": "array", "items": {"type": "object"}},
            "message": _STRING,
            "reconciliation_token": _STRING,
        },
        ("claims", "message"),
    ),
    "freshness": _schema({"now": _STRING}),
    "ledger": _schema(),
    "revoke": _schema({"claim_id": _STRING, "reason": _STRING}, ("claim_id", "reason")),
    "verify": _schema(),
}


def tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": f"braid_{operation}",
            "description": f"Run canonical Braid context operation: {operation}.",
            "inputSchema": TOOL_SCHEMAS[operation],
        }
        for operation in OPERATIONS
    ]


def resource_definitions() -> list[dict[str, Any]]:
    return [
        {
            "uri": uri,
            "name": name.title(),
            "mimeType": "application/json",
            "description": f"Canonical Braid {name} view.",
        }
        for uri, name in RESOURCES.items()
    ]


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    return to_dict() if callable(to_dict) else value


def call_ledger_operation(ledger: Any, operation: str, arguments: Any) -> Any:
    if operation not in OPERATIONS:
        raise McpProtocolError(f"Unknown Braid operation: {operation}")
    if not isinstance(arguments, Mapping):
        raise McpProtocolError("Tool arguments must be an object.")
    schema = TOOL_SCHEMAS[operation]
    unknown = set(arguments) - set(schema["properties"])
    if unknown:
        raise McpProtocolError(
            "Unknown tool argument(s): " + ", ".join(sorted(unknown))
        )
    missing = set(schema["required"]) - set(arguments)
    if missing:
        raise McpProtocolError(
            "Missing required tool argument(s): " + ", ".join(sorted(missing))
        )
    _validate_schema_value(dict(arguments), schema, "arguments")
    dispatch = getattr(ledger, "dispatch", None)
    if callable(dispatch):
        return _jsonable(dispatch(operation, dict(arguments)))
    method = getattr(ledger, operation, None)
    if not callable(method):
        raise McpProtocolError(f"Canonical ledger does not expose `{operation}`.")
    return _jsonable(method(**dict(arguments)))


def _validate_schema_value(value: Any, schema: Mapping[str, Any], path: str) -> None:
    expected = schema.get("type")
    valid = {
        "object": isinstance(value, Mapping),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
    }.get(expected, True)
    if not valid:
        raise McpProtocolError(f"{path} must be {expected}.")
    if expected == "object" and isinstance(value, Mapping):
        properties = schema.get("properties", {})
        for key, member in value.items():
            member_schema = properties.get(key)
            if isinstance(member_schema, Mapping):
                _validate_schema_value(member, member_schema, f"{path}.{key}")
    elif expected == "array" and isinstance(value, list):
        member_schema = schema.get("items")
        if isinstance(member_schema, Mapping):
            for index, member in enumerate(value):
                _validate_schema_value(member, member_schema, f"{path}[{index}]")


def read_ledger_resource(ledger: Any, uri: str) -> Any:
    if uri not in RESOURCES:
        raise McpProtocolError(f"Unknown Braid resource: {uri}")
    name = RESOURCES[uri]
    reader = getattr(ledger, "read_resource", None)
    if callable(reader):
        return _jsonable(reader(name))
    method = getattr(ledger, name, None)
    if callable(method):
        return _jsonable(method())
    return call_ledger_operation(ledger, name, {})


def _response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def handle_request(
    ledger: Any,
    request: Any,
    session: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    session = session if session is not None else {"phase": "new"}
    if (
        not isinstance(request, Mapping)
        or request.get("jsonrpc") != "2.0"
        or not isinstance(request.get("method"), str)
    ):
        return _error(
            request.get("id") if isinstance(request, Mapping) else None,
            -32600,
            "Invalid JSON-RPC request.",
        )
    request_id, notification = request.get("id"), "id" not in request
    if not notification and (
        isinstance(request_id, bool)
        or not isinstance(request_id, (str, int, float, type(None)))
    ):
        return _error(None, -32600, "JSON-RPC id must be a string, number, or null.")
    params = request.get("params", {})
    if not isinstance(params, Mapping):
        return (
            None
            if notification
            else _error(request_id, -32602, "Request params must be an object.")
        )
    try:
        method = request["method"]
        if method == "initialize":
            if notification or session.get("phase", "new") != "new":
                return (
                    None
                    if notification
                    else _error(
                        request_id, -32600, "Initialize must be the first request."
                    )
                )
            if (
                not isinstance(params.get("protocolVersion"), str)
                or not isinstance(params.get("capabilities"), Mapping)
                or not isinstance(params.get("clientInfo"), Mapping)
                or not isinstance(params["clientInfo"].get("name"), str)
                or not isinstance(params["clientInfo"].get("version"), str)
            ):
                return _error(request_id, -32602, "Invalid MCP initialize params.")
            session["phase"] = "initialized"
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"listChanged": False},
                },
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            }
        elif method == "notifications/initialized":
            if not notification:
                return _error(
                    request_id,
                    -32600,
                    "notifications/initialized must not contain an id.",
                )
            if session.get("phase") == "initialized":
                session["phase"] = "ready"
            return None
        elif session.get("phase") != "ready":
            return (
                None
                if notification
                else _error(request_id, -32002, "MCP server is not initialized.")
            )
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": tool_definitions()}
        elif method == "resources/list":
            result = {"resources": resource_definitions()}
        elif method == "tools/call":
            name = params.get("name")
            if not isinstance(name, str) or not name.startswith("braid_"):
                raise McpProtocolError("Unknown tool.")
            value = call_ledger_operation(
                ledger, name.removeprefix("braid_"), params.get("arguments", {})
            )
            text = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            result = {
                "content": [{"type": "text", "text": text}],
                "structuredContent": value,
                "isError": False,
            }
        elif method == "resources/read":
            uri = params.get("uri")
            if not isinstance(uri, str):
                raise McpProtocolError("Resource URI must be a string.")
            value = read_ledger_resource(ledger, uri)
            result = {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(
                            value,
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=False,
                            allow_nan=False,
                        ),
                    }
                ]
            }
        else:
            return (
                None
                if notification
                else _error(request_id, -32601, "Method not found.")
            )
    except McpProtocolError as error:
        return None if notification else _error(request_id, -32602, str(error))
    except (TypeError, ValueError) as error:
        return None if notification else _error(request_id, -32602, str(error))
    except Exception:
        return (
            None
            if notification
            else _error(request_id, -32603, "Canonical ledger operation failed.")
        )
    return None if notification else _response(request_id, result)


def serve(
    ledger: Any, input_stream: TextIO = sys.stdin, output_stream: TextIO = sys.stdout
) -> None:
    session = {"phase": "new"}
    while True:
        line = input_stream.readline(MAX_REQUEST_CHARS + 1)
        if not line:
            break
        if len(line) > MAX_REQUEST_CHARS:
            while line and not line.endswith("\n"):
                line = input_stream.readline(MAX_REQUEST_CHARS + 1)
            answer = _error(None, -32700, "Request exceeds the MCP size limit.")
        else:
            try:
                request = strict_json_loads(line)
            except (json.JSONDecodeError, SecurityError):
                answer = _error(None, -32700, "Parse error.")
            else:
                answer = handle_request(ledger, request, session)
        if answer is not None:
            output_stream.write(
                json.dumps(
                    answer, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                )
                + "\n"
            )
            output_stream.flush()


def main() -> int:
    import argparse
    from context_store import ContextLedger

    parser = argparse.ArgumentParser(
        description="Expose a local Braid ContextLedger over stdio MCP."
    )
    parser.add_argument(
        "--project", required=True, help="Logical local ContextLedger project name."
    )
    parser.add_argument(
        "--principal", help="Expected key-derived local recipient ID (optional pin)."
    )
    parser.add_argument("--home", type=Path, help="Local ledger state root.")
    args = parser.parse_args()
    serve(
        ContextLedgerMcpAdapter(
            ContextLedger(args.project, args.home, principal=args.principal)
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
