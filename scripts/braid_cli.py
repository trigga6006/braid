#!/usr/bin/env python3
"""Single front door for Braid.

This module owns no argument parsing of its own beyond the group name. It
resolves the first argument to a target module, rewrites ``sys.argv`` so the
target's existing parser sees exactly the arguments it already understands, and
then calls that module's ``main()``. Keeping the dispatch this thin is
deliberate: every group below is one already-tested parser, reached unchanged.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import NamedTuple

VERSION = "0.5.0"

if __package__ in (None, "") and str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))


class Group(NamedTuple):
    module: str
    prepend: tuple[str, ...]
    prog: str
    summary: str


GROUPS: dict[str, Group] = {
    "handoff": Group(
        "braid_session",
        ("handoff",),
        "braid",
        "Capture one local session into your own local context ledger",
    ),
    "session": Group(
        "braid_session",
        (),
        "braid session",
        "Discover, resolve, export, or ask a local Claude/Codex session",
    ),
    "ledger": Group(
        "context_bridge",
        (),
        "braid ledger",
        "Extract, review, commit, minimize, export, and reconcile claims",
    ),
    "incident": Group(
        "team_connector",
        ("incident",),
        "braid",
        "Ask for, render, and check an on-call incident handoff",
    ),
    "team": Group(
        "team_connector",
        (),
        "braid team",
        "Enroll, trust, sync, request, respond, and publish through a Team Hub",
    ),
    "net": Group(
        "network_bridge",
        (),
        "braid net",
        "Pair two installations over a temporary direct or public HTTPS room",
    ),
    "hub": Group(
        "team_hub",
        (),
        "braid hub",
        "Run and administer the self-hosted Team Hub mailbox",
    ),
    "mcp": Group(
        "context_mcp",
        (),
        "braid mcp",
        "Expose a local context ledger over stdio MCP",
    ),
}

HELP_FLAGS = frozenset({"-h", "--help", "help"})
VERSION_FLAGS = frozenset({"-V", "--version", "version"})


def usage() -> str:
    width = max(len(name) for name in GROUPS)
    lines = [
        "usage: braid <group> [args...]",
        "",
        "Governed context synchronization for existing Claude Code and Codex sessions.",
        "",
        "groups:",
    ]
    lines.extend(
        f"  {name.ljust(width)}  {group.summary}" for name, group in GROUPS.items()
    )
    lines.extend(
        [
            "",
            "Start here:",
            '  braid handoff --from "<session>" --project "<ledger-project>"',
            "",
            "Run 'braid <group> --help' for the commands inside a group.",
        ]
    )
    return "\n".join(lines)


def _exit_code(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(not value)
    if isinstance(value, int):
        return value
    print(value, file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)

    if not arguments or arguments[0] in HELP_FLAGS:
        print(usage())
        return 0
    if arguments[0] in VERSION_FLAGS:
        print(f"braid {VERSION}")
        return 0

    name = arguments[0]
    group = GROUPS.get(name)
    if group is None:
        print(f"braid: unknown group '{name}'", file=sys.stderr)
        print(f"choose one of: {', '.join(GROUPS)}", file=sys.stderr)
        return 2

    module = importlib.import_module(group.module)
    saved = sys.argv
    sys.argv = [group.prog, *group.prepend, *arguments[1:]]
    try:
        return _exit_code(module.main())
    except SystemExit as error:
        return _exit_code(error.code)
    finally:
        sys.argv = saved


if __name__ == "__main__":
    raise SystemExit(main())
