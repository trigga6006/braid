#!/usr/bin/env python3
"""Braid Context Ledger CLI: version, minimize, disclose, and reconcile agent context."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from context_extract import extract_markdown_claims, extract_message_claims
from context_store import ContextLedger, _atomic_json


VERSION = "0.4.0"


def _local(value: str) -> Path:
    if "://" in value:
        raise ValueError("Only local filesystem paths are accepted.")
    return Path(value).expanduser()


def _json_file(value: str) -> Any:
    return json.loads(_local(value).read_text(encoding="utf-8"))


def _claims_file(value: str) -> list[dict[str, Any]]:
    claims = _json_file(value)
    if isinstance(claims, dict):
        claims = claims.get("claims")
    if not isinstance(claims, list):
        raise ValueError(
            "Claims file must contain a JSON list or an object with a claims list."
        )
    return claims


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def _ledger(args: argparse.Namespace) -> ContextLedger:
    return ContextLedger(
        args.project,
        _local(args.home) if args.home else None,
        args.principal,
    )


def _next_argv(args: argparse.Namespace, *tail: str) -> list[str]:
    argv = ["braid", "--project", args.project]
    if args.principal:
        argv.extend(("--principal", args.principal))
    if args.home:
        argv.extend(("--home", str(_local(args.home))))
    return [*argv, *tail]


def cmd_extract(args: argparse.Namespace) -> None:
    if bool(args.markdown) == bool(args.session):
        raise ValueError("Choose exactly one source: --markdown or --session.")
    if args.markdown:
        claims = extract_markdown_claims(
            _local(args.markdown).read_text(encoding="utf-8")
        )
    else:
        import session_bridge

        session = session_bridge.resolve_session(args.session, args.provider)
        if session.transcript is None:
            raise ValueError("The selected session has no locally readable transcript.")
        messages = (
            session_bridge.extract_codex(session.transcript)
            if session.provider == "codex"
            else session_bridge.extract_claude(session.transcript)
        )
        claims = extract_message_claims(messages)
    result = {"claims": claims, "count": len(claims), "requires_review": True}
    if args.stage:
        result["stage"] = _ledger(args).stage(claims, args.message)
    if args.output:
        _atomic_json(_local(args.output), result)
    shown = {
        "count": len(claims),
        "requires_review": True,
        "staged": bool(args.stage),
        **(
            {"claims": claims}
            if not args.output and not args.stage
            else ({"output": str(_local(args.output))} if args.output else {})
        ),
    }
    if args.stage:
        shown["stage_id"] = result["stage"]["stage_id"]
        shown["next_argv"] = _next_argv(
            args, "review-staged", result["stage"]["stage_id"]
        )
    _print(shown)


def cmd_stage(args: argparse.Namespace) -> None:
    result = _ledger(args).stage(_claims_file(args.claims), args.message)
    _print(
        {
            "stage_id": result["stage_id"],
            "claims": len(result["claims"]),
            "reviewed": result["reviewed"],
            "next_argv": _next_argv(args, "review-staged", result["stage_id"]),
        }
    )


def cmd_review_stage(args: argparse.Namespace) -> None:
    result = _ledger(args).review_staged(args.stage_id)
    result["next_argv"] = _next_argv(
        args,
        "approve-staged",
        args.stage_id,
        "--review-digest",
        result["review_digest"],
    )
    _print(result)


def cmd_approve_stage(args: argparse.Namespace) -> None:
    result = _ledger(args).approve_staged(args.stage_id, args.review_digest)
    result["next_argv"] = _next_argv(
        args,
        "commit",
        "--author",
        "<principal>",
        "--stage-id",
        args.stage_id,
    )
    _print(result)


def cmd_commit(args: argparse.Namespace) -> None:
    revision = _ledger(args).commit(
        args.author,
        _json_file(args.governance) if args.governance else {},
        args.message,
        args.stage_id,
    )
    _print(
        {
            "revision": revision["id"],
            "sequence": revision["revision"]["sequence"],
            "claims": len(revision["claims"]),
            "parents": revision["revision"]["parent_ids"],
            "next_argv": _next_argv(args, "plan", "--recipient", "<remote-principal>"),
        }
    )


def cmd_status(args: argparse.Namespace) -> None:
    _print(_ledger(args).status())


def cmd_log(args: argparse.Namespace) -> None:
    _print(_ledger(args).log())


def cmd_show(args: argparse.Namespace) -> None:
    _print(_ledger(args).show(args.revision))


def cmd_diff(args: argparse.Namespace) -> None:
    _print(_ledger(args).diff(args.before, args.after))


def cmd_freshness(args: argparse.Namespace) -> None:
    _print(_ledger(args).freshness(args.at))


def cmd_verify(args: argparse.Namespace) -> None:
    _print({"audit_valid": _ledger(args).verify_audit()})


def cmd_plan(args: argparse.Namespace) -> None:
    profile = {
        "principal_id": args.recipient,
        "purpose": args.purpose,
        "max_sensitivity": args.max_sensitivity,
        "max_claims": args.max_claims,
        "max_bytes": args.max_bytes,
        "audiences": args.audience,
    }
    _print(_ledger(args).plan(profile, args.claim or None))


def cmd_export(args: argparse.Namespace) -> None:
    _print(
        _ledger(args).export(
            args.revision,
            _local(args.output),
            args.recipient,
            args.claim or None,
            args.purpose,
            args.max_sensitivity,
        )
    )


def cmd_import(args: argparse.Namespace) -> None:
    ledger = _ledger(args)
    token = ledger.import_quarantine(_local(args.source))
    _print(
        {
            "quarantine_token": token,
            "reviewed": False,
            "next_argv": _next_argv(args, "review-import", token),
        }
    )


def cmd_review(args: argparse.Namespace) -> None:
    _print(_ledger(args).review_import(args.token))


def cmd_accept(args: argparse.Namespace) -> None:
    revision = _ledger(args).accept_import(
        args.token, allow_sensitive=args.allow_sensitive
    )
    _print(
        {
            "accepted": revision["id"],
            "claims": len(revision["claims"]),
            "next_argv": _next_argv(args, "freshness"),
        }
    )


def cmd_disclose(args: argparse.Namespace) -> None:
    result = _ledger(args).disclose(
        args.recipient,
        args.revision,
        args.claim or None,
        args.purpose,
        args.max_sensitivity,
    )
    if args.output:
        _atomic_json(_local(args.output), result.pop("bundle"))
        result["output"] = str(_local(args.output))
    _print(result)


def cmd_who_has(args: argparse.Namespace) -> None:
    _print({"claim": args.claim, "recipients": _ledger(args).who_has_claim(args.claim)})


def cmd_revoke(args: argparse.Namespace) -> None:
    _ledger(args).revoke(args.claim, args.reason)
    _print({"claim": args.claim, "revoked": True})


def cmd_reconcile(args: argparse.Namespace) -> None:
    _print(_ledger(args).prepare_reconciliation(args.local, args.remote))


def cmd_resolve(args: argparse.Namespace) -> None:
    result = _ledger(args).stage(
        _claims_file(args.claims),
        "resolve: " + args.message,
        reconciliation_token=args.reconciliation_token,
    )
    _print(
        {
            "stage_id": result["stage_id"],
            "claims": len(result["claims"]),
            "reviewed": False,
            "next_argv": _next_argv(args, "review-staged", result["stage_id"]),
        }
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project",
        required=True,
        help="Logical project name; never a filesystem path.",
    )
    parser.add_argument(
        "--principal",
        help="Expected cryptographic local recipient identifier.",
    )
    parser.add_argument(
        "--home",
        help="Local ledger state root; equivalent to SESSION_BRIDGE_HOME.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    commands = parser.add_subparsers(dest="cmd", required=True)

    def add(
        name: str,
        function: Any,
        help_text: str,
        *arguments: tuple[tuple[str, ...], dict[str, Any]],
    ) -> None:
        command = commands.add_parser(
            name,
            help=help_text,
            description=help_text,
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )
        for flags, options in arguments:
            command.add_argument(*flags, **options)
        command.set_defaults(fn=function)

    add(
        "extract",
        cmd_extract,
        "Extract reviewable claims from a session or curated Markdown",
        (("--session",), {}),
        (("--provider",), {"choices": ("all", "codex", "claude"), "default": "all"}),
        (("--markdown",), {}),
        (("--output",), {}),
        (("--stage",), {"action": "store_true"}),
        (("--message",), {"default": "extracted context"}),
    )
    add(
        "stage",
        cmd_stage,
        "Stage claims for inspection and approval",
        (
            ("--claims",),
            {"required": True, "help": "Local JSON file containing claims."},
        ),
        (("--message",), {"default": "", "help": "Human-readable stage purpose."}),
    )
    add(
        "review-staged",
        cmd_review_stage,
        "Display and validate one isolated stage without approving it",
        (
            ("stage_id",),
            {"help": "Stage identifier returned by stage or extract --stage."},
        ),
    )
    add(
        "approve-staged",
        cmd_approve_stage,
        "Approve the exact digest returned by review-staged",
        (("stage_id",), {"help": "The stage that was just reviewed."}),
        (
            ("--review-digest",),
            {
                "required": True,
                "help": "Exact sha256 digest returned by review-staged; changed content is rejected.",
            },
        ),
    )
    add(
        "commit",
        cmd_commit,
        "Commit staged claims as an immutable revision",
        (
            ("--author",),
            {"required": True, "help": "Display name recorded on the revision."},
        ),
        (("--governance",), {"help": "Optional local governance JSON file."}),
        (
            ("--message",),
            {"default": None, "help": "Override the staged commit message."},
        ),
        (("--stage-id",), {"help": "Approved isolated stage to commit."}),
    )
    for name, fn, help_text in (
        ("status", cmd_status, "Show ledger state"),
        ("log", cmd_log, "Show revision log"),
        ("verify", cmd_verify, "Verify the audit hash chain"),
    ):
        add(name, fn, help_text)
    add("show", cmd_show, "Show one revision", (("revision",), {}))
    add(
        "diff",
        cmd_diff,
        "Compute an ancestry-aware semantic diff",
        (("before",), {}),
        (("after",), {}),
    )
    add(
        "freshness",
        cmd_freshness,
        "Show active, expired, superseded, and revoked claims",
        (("--at",), {}),
    )
    disclosure_args = (
        (("--recipient",), {"required": True}),
        (("--claim",), {"action": "append"}),
        (("--purpose",), {"default": "Context reconciliation"}),
        (
            ("--max-sensitivity",),
            {
                "choices": ("public", "internal", "confidential", "restricted"),
                "default": "internal",
            },
        ),
    )
    add(
        "plan",
        cmd_plan,
        "Preview recipient-minimized context without sending",
        *disclosure_args,
        (("--audience",), {"action": "append", "default": []}),
        (("--max-claims",), {"type": int, "default": 100}),
        (("--max-bytes",), {"type": int, "default": 200000}),
    )
    add(
        "export",
        cmd_export,
        "Create a signed recipient-bound disclosure bundle",
        (("revision",), {}),
        (("--output",), {"required": True}),
        *disclosure_args,
    )
    add(
        "import",
        cmd_import,
        "Verify and quarantine a signed local bundle",
        (
            ("source",),
            {"help": "Local disclosure bundle or single-event watch response."},
        ),
    )
    add(
        "review-import",
        cmd_review,
        "Reverify and display redacted quarantined claims before accepting",
        (("token",), {"help": "Quarantine token returned by import."}),
    )
    add(
        "accept",
        cmd_accept,
        "Explicitly trust and accept a quarantined import",
        (("token",), {"help": "Reviewed quarantine token."}),
        (
            ("--allow-sensitive",),
            {
                "action": "store_true",
                "help": "Explicitly accept claims flagged as sensitive after reviewing redactions.",
            },
        ),
    )
    add(
        "disclose",
        cmd_disclose,
        "Issue and record a signed disclosure",
        (("revision",), {}),
        *disclosure_args,
        (("--output",), {}),
    )
    add(
        "who-has-claim", cmd_who_has, "List recipients issued a claim", (("claim",), {})
    )
    add(
        "revoke",
        cmd_revoke,
        "Record a local revocation tombstone",
        (("claim",), {}),
        (("--reason",), {"required": True}),
    )
    add(
        "reconcile",
        cmd_reconcile,
        "Plan a conflict-preserving merge",
        (
            ("--local",),
            {
                "action": "append",
                "required": True,
                "help": "Local head revision; repeatable.",
            },
        ),
        (
            ("--remote",),
            {
                "action": "append",
                "required": True,
                "help": "Remote head revision; repeatable.",
            },
        ),
    )
    add(
        "resolve",
        cmd_resolve,
        "Stage an explicit human-authored conflict resolution",
        (
            ("--claims",),
            {"required": True, "help": "Local JSON file containing resolution claims."},
        ),
        (
            ("--message",),
            {"required": True, "help": "Why each conflict remains or is superseded."},
        ),
        (
            ("--reconciliation-token",),
            {
                "required": True,
                "help": "One-use token returned by reconcile for the current two heads.",
            },
        ),
    )
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        args.fn(args)
        return 0
    except (ValueError, PermissionError, OSError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
