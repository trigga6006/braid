#!/usr/bin/env python3
"""Zero-ceremony context handoff between two local sessions of one principal.

A handoff copies the working context of one local agent session into the local
context ledger in a single invocation, without the interactive review round
trip.  That shortcut is sound only because both endpoints are the SAME
principal on the SAME machine, so no trust boundary is crossed.  This module
proves that precondition before it touches the ledger instead of assuming it,
and refuses -- pointing at the governed path -- whenever the proof fails.

Nothing in the safety pipeline is removed.  Extraction still blocks
credential-bearing events, still redacts PII, and still refuses to turn
prompt-injection-shaped spans into claims.  The ledger's approval gate is
*automated*, not bypassed: the genuine digest returned by ``review_staged`` is
what ``approve_staged`` receives, so every claim validation, every
``scan_sensitive`` chokepoint, and every audit-chain entry runs exactly as it
does on the governed path.

``--dry-run`` stages and reviews for real -- that is how those scanners get to
run -- and then discards the stage.  It reports; it never leaves an approvable
artifact behind, because approving from a digest of eight truncated previews
would be exactly the unreviewed commit this module exists to prevent.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import secrets
from typing import Any, NoReturn

import context_extract
from context_extract import extract_messages, to_context_claims
from context_security import identity_principal, load_or_create_identity
from context_store import ContextLedger, _lock, _safe_project
import braid_session
from terminal_safe import terminal_safe


HANDOFF_FORMAT = "braid-handoff/v1"
# A handoff is "catch the other session up on what we just did", not an
# archive.  A tight default keeps the capture inside the extractor's reviewable
# candidate budget and keeps the printed digest to roughly one screen.
DEFAULT_MAX_CHARS = 24_000
MAX_PREVIEW_CLAIMS = 8
PREVIEW_CHARS = 96

# The only principal form this endpoint can ever be: a key-derived identifier.
LOCAL_PRINCIPAL = re.compile(r"ed25519:[0-9a-f]{64}")

# Windows GetDriveTypeW: the volume behind this root is another host's storage.
_DRIVE_REMOTE = 4

GOVERNED_PATH_HINT = (
    "Zero ceremony is only for two sessions of the same principal on the same "
    "machine. Use the governed path across a trust boundary: braid extract "
    "--session <id> --stage, braid review-staged <stage>, braid approve-staged "
    "<stage> --review-digest <digest>, braid commit --author <you>, then braid "
    "plan --recipient <remote-principal> and braid export."
)


class HandoffRefused(PermissionError):
    """The same-principal/local-only precondition does not hold."""


def _refuse(reason: str) -> NoReturn:
    raise HandoffRefused(f"{reason}\n{GOVERNED_PATH_HINT}")


def _is_local_text(text: str) -> bool:
    """Reject one path *spelling* that names storage on another host."""
    if "://" in text:
        return False
    # A UNC/network share is another host's storage even when it is mounted.
    if text.startswith("\\\\") or text.startswith("//"):
        return False
    drive = os.path.splitdrive(text)[0]
    return not (drive.startswith("\\\\") or drive.startswith("//"))


def _is_remote_volume(path: Path) -> bool:
    """True when a resolved drive letter is really a mapped network drive."""
    if os.name != "nt":
        return False
    drive = os.path.splitdrive(str(path))[0]
    if not drive or not drive.endswith(":"):
        # No drive letter at all, or a UNC root ``_is_local_text`` already
        # refuses; nothing left for the volume query to decide.
        return False
    try:
        import ctypes

        return int(ctypes.windll.kernel32.GetDriveTypeW(drive + "\\")) == _DRIVE_REMOTE
    except (AttributeError, OSError, ValueError):
        # Without an answer, fall back to the textual verdict rather than
        # refusing every path on a machine where the query is unavailable.
        return False


def _is_local_path(value: Path | str) -> bool:
    """Reject anything that is not a plain path on this machine's filesystem.

    The literal string is not enough.  A directory junction or symlink whose
    target is ``\\\\host\\share`` reads as an ordinary local path right up until
    it is resolved -- and ``_within`` compares *resolved* paths, so an
    unresolved locality check and a resolved containment check can both pass
    for content that actually lives on a network share.  Resolve first, then
    apply the same locality rule to what the path really points at.
    """
    text = str(value)
    if not _is_local_text(text):
        return False
    try:
        resolved = Path(value).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    if not _is_local_text(str(resolved)):
        return False
    return not _is_remote_volume(resolved)


def _local_session_roots() -> list[Path]:
    """Return the session stores owned by the current OS user."""
    return [
        braid_session.codex_home(),
        braid_session.claude_home(),
        *braid_session.claude_desktop_roots(),
        braid_session.hermes_home(),
    ]


# TODO(security): the locality proof is still "same machine", not "same user".
# Verifying that the transcript, the session root, and the ledger store are
# OWNED by the current SID/UID needs OS-level primitives this module does not
# reach for yet.
# TODO(security): every check here is check-then-open, so a path can be
# swapped between the locality proof and the read.  Closing that means
# validating from an already-open handle, which is a larger design change.
def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _discard_stage(ledger: ContextLedger, stage_id: str) -> None:
    """Delete a stage this call created so nothing approvable is left behind.

    Used by ``--dry-run``: the staging and review really run, so every scanner
    on the gate executes, but the artifact they produced is thrown away.  A
    stage that survived a dry run would be approvable and committable from the
    printed digest alone -- content the user has only seen eight truncated
    previews of.
    """
    path = ledger.staging / f"{stage_id}.json"
    with _lock(ledger.lock_path):
        path.unlink(missing_ok=True)
    if path.exists():  # pragma: no cover - unlink raises instead
        raise OSError(
            f"The dry run could not discard its temporary stage {stage_id}; "
            "it is still approvable. Remove it before trusting this ledger."
        )


def assert_source_is_local(session: Any) -> None:
    """Prove the source session is this user's own local session on this host."""
    transcript = getattr(session, "transcript", None)
    if transcript is None and getattr(session, "export_mode", "file") == "cli":
        # Hermes keeps its conversations in a SQLite store rather than one file
        # per session, so the locality proof is anchored on that store instead.
        _assert_cli_source_is_local(session)
        return
    if transcript is None:
        _refuse(
            "The source session has no local transcript (it lives only in a "
            "remote surface). Continue or import it locally first."
        )
    transcript = Path(transcript)
    # The refusal text is printed to a terminal and a file name is not this
    # process's own text, so it is escaped like any other untrusted string.
    shown = terminal_safe(transcript, 200)
    if not _is_local_path(transcript):
        _refuse(f"The source transcript {shown} is not on local storage.")
    if not transcript.is_file():
        _refuse(f"The source transcript {shown} is not a readable file.")
    # A session root that itself resolves onto a share cannot vouch for
    # anything: containment inside it would only prove the transcript is on the
    # same remote subtree.
    roots = [root for root in _local_session_roots() if _is_local_path(root)]
    if not any(_within(transcript, root) for root in roots):
        _refuse(
            f"The source transcript {shown} is outside this user's own "
            "session stores, so it may belong to a different principal."
        )


def _assert_cli_source_is_local(session: Any) -> None:
    """Prove a CLI-exported session is this user's own, on this host.

    A local store is necessary but not sufficient.  Hermes keeps gateway
    conversations (Telegram, Discord, Slack, the web UI, cron) in the very same
    local database, and their turns were authored by remote third parties.
    Location cannot vouch for authorship, so the origin is checked too and the
    zero-ceremony path is reserved for first-party sessions.
    """
    if getattr(session, "provider", "") != "hermes":
        _refuse("This session's provider cannot prove a local source store.")
    source = braid_session.hermes_source(session)
    if source not in braid_session.HERMES_LOCAL_SOURCES:
        _refuse(
            f"This Hermes session came from '{terminal_safe(source, 40)}', so its "
            "turns were authored through a remote gateway rather than by you at "
            "this machine. A local database cannot prove same-principal "
            "authorship. Use the governed path (extract, review, disclose) "
            "instead of the zero-ceremony handoff."
        )
    store = braid_session.hermes_state_db()
    shown = terminal_safe(store, 200)
    if not _is_local_path(store):
        _refuse(f"The Hermes session store {shown} is not on local storage.")
    if not store.is_file():
        _refuse(f"The Hermes session store {shown} is not a readable file.")
    home = braid_session.hermes_home()
    if not _is_local_path(home) or not _within(store, home):
        _refuse(
            f"The Hermes session store {shown} is outside this user's own "
            "Hermes home, so it may belong to a different principal."
        )


def assert_destination_is_same_principal(
    ledger: ContextLedger, destination_principal: str | None = None
) -> dict[str, Any]:
    """Prove the destination ledger is this endpoint's own key-bound ledger."""
    if not _is_local_path(ledger.root) or not _is_local_path(
        ledger.recipient_identity_path
    ):
        _refuse("The destination ledger is not on local storage.")
    if not LOCAL_PRINCIPAL.fullmatch(ledger.principal):
        _refuse("The destination ledger has no local key-derived principal.")
    # Re-derive the principal from the private key on disk rather than trusting
    # the value cached on the ledger object.
    live = identity_principal(load_or_create_identity(ledger.recipient_identity_path))
    if not secrets.compare_digest(live, ledger.principal):
        _refuse("The destination ledger is bound to a different local key.")
    if destination_principal is not None:
        wanted = destination_principal.strip()
        if not LOCAL_PRINCIPAL.fullmatch(wanted):
            _refuse(
                f"{destination_principal!r} is not a local key-derived "
                "principal, so it is a different party."
            )
        if not secrets.compare_digest(wanted, ledger.principal):
            _refuse(
                "The requested destination principal is not this endpoint "
                f"({ledger.principal})."
            )
    try:
        # status() revalidates the persisted principal/key binding in state.json.
        status = ledger.status()
    except (OSError, ValueError) as error:
        _refuse(f"The destination ledger is not this endpoint's own: {error}")
    if not status["audit_valid"]:
        raise HandoffRefused(
            "The destination ledger's audit chain does not verify; refusing to "
            "write. Inspect it with: braid --project "
            f"{ledger.project} verify"
        )
    if len(status["heads"]) >= 2:
        _refuse(
            "The destination ledger has two heads. Divergence is a governance "
            "event: run braid reconcile and braid resolve first."
        )
    return status


def _open_local_ledger(project: str, home: Path | str | None) -> ContextLedger:
    _safe_project(project)
    root: Path | None = None
    if home is not None:
        if not _is_local_path(home):
            _refuse(
                f"The ledger home {terminal_safe(home, 200)} is not a local "
                "filesystem path."
            )
        root = Path(home).expanduser()
    try:
        return ContextLedger(project, root)
    except (OSError, ValueError) as error:
        # ContextLedger refuses a ledger whose recorded principal or key binding
        # is not this endpoint's; that is exactly the cross-principal case.
        _refuse(
            "The destination ledger could not be opened as this endpoint's own "
            f"local ledger: {error}"
        )


def _drop_injection_shaped(
    claims: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """Defense in depth: never let instruction-shaped text become a claim.

    ``context_extract`` already refuses to build a candidate from an
    injection-shaped span.  This re-checks the final statements so a regression
    upstream cannot quietly promote such text into an ``action`` (or any other)
    claim on the low-ceremony path.
    """
    kept: list[dict[str, Any]] = []
    dropped = 0
    for claim in claims:
        if context_extract._INJECTION.search(str(claim.get("statement", ""))):
            dropped += 1
            continue
        kept.append(claim)
    return kept, dropped


def _counts(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _summarize(
    extraction: context_extract.ExtractionResult,
    claims: list[dict[str, Any]],
    dropped: int,
) -> dict[str, Any]:
    notices = _counts(notice.code for notice in extraction.notices)
    if dropped:
        notices["injection_shaped_claim_dropped"] = dropped
    return {
        "captured": {
            "claims": len(claims),
            "kinds": _counts(str(claim["kind"]) for claim in claims),
            "status_labeled": sum(
                1 for claim in claims if "status" in claim.get("labels", [])
            ),
            "untrusted": sum(
                1 for claim in claims if "untrusted-source" in claim.get("labels", [])
            ),
            "redactions": _counts(
                label for claim in claims for label in claim.get("redactions", [])
            ),
        },
        "notices": notices,
    }


def _preview(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "kind": terminal_safe(claim["kind"], 24),
            "statement": terminal_safe(claim["statement"], PREVIEW_CHARS),
            "untrusted": "untrusted-source" in claim.get("labels", []),
        }
        for claim in claims[:MAX_PREVIEW_CLAIMS]
    ]


def _next_argv(project: str, home: Path | str | None, *tail: str) -> list[str]:
    # The upgrade path continues in the ``ledger`` group, and the front door
    # resolves argv[1] as a group name, so it has to be named here for the
    # array to be runnable verbatim.
    argv = ["braid", "ledger", "--project", project]
    if home is not None:
        argv.extend(("--home", str(home)))
    return [*argv, *tail]


def _commit_message(session: Any) -> str:
    provider = terminal_safe(getattr(session, "provider", ""), 32)
    identifier = terminal_safe(getattr(session, "session_id", ""), 64)
    return f"Local handoff from {provider} session {identifier}".strip()


def run_handoff(
    source: str,
    project: str,
    *,
    provider: str = "all",
    max_chars: int | None = None,
    home: Path | str | None = None,
    destination_principal: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Resolve, extract, stage, review, approve, and commit in one invocation."""
    budget = DEFAULT_MAX_CHARS if max_chars is None else int(max_chars)
    if budget <= 0:
        raise ValueError("--max-chars must be a positive number of characters.")

    session = braid_session.resolve_session(source, provider)
    assert_source_is_local(session)
    ledger = _open_local_ledger(project, home)
    status = assert_destination_is_same_principal(ledger, destination_principal)

    messages = braid_session.extract_session_messages(session)
    chosen, omitted = braid_session.limited_messages(messages, budget)
    try:
        extraction = extract_messages(chosen)
        claims = to_context_claims(extraction)
    except ValueError as error:
        raise ValueError(
            f"{error} Re-run with a smaller --max-chars to hand off a tighter "
            "slice of the session."
        ) from error
    claims, dropped = _drop_injection_shaped(claims)
    summary = _summarize(extraction, claims, dropped)

    result: dict[str, Any] = {
        "format": HANDOFF_FORMAT,
        "dry_run": dry_run,
        "committed": False,
        "project": ledger.project,
        "principal": ledger.principal,
        "same_principal_local": True,
        "source": {
            "provider": session.provider,
            "surface": session.surface,
            "session_id": session.session_id,
            "title": session.title,
            "cwd": session.cwd,
            "transcript": str(session.transcript),
            "messages_total": len(messages),
            "messages_read": len(chosen),
            "messages_omitted": omitted,
        },
        **summary,
        "preview": _preview(claims),
        "stage_id": None,
        "review_digest": None,
        "revision": None,
        "sequence": None,
        "parents": [],
        "audit_valid": bool(status["audit_valid"]),
        "next_argv": _next_argv(
            ledger.project, home, "plan", "--recipient", "<remote-principal>"
        ),
    }
    if not claims:
        result["reason"] = "nothing-to-capture"
        return result

    staged = ledger.stage(claims, _commit_message(session))
    stage_id = str(staged["stage_id"])
    if dry_run:
        # Stage and review for real -- that is the whole point of a dry run, and
        # it is how every claim validation and credential scan on the gate gets
        # to run -- then throw the stage away.  A dry run reports; it must never
        # leave an artifact that can be approved and committed from the digest
        # alone, since the digest shows only truncated previews.
        try:
            ledger.review_staged(stage_id)
        finally:
            _discard_stage(ledger, stage_id)
        result["reason"] = "dry-run"
        result["audit_valid"] = ledger.verify_audit()
        return result

    result["stage_id"] = stage_id
    # The genuine review digest: approve_staged rejects anything else, so the
    # gate is satisfied here rather than circumvented.
    review = ledger.review_staged(stage_id)
    result["review_digest"] = review["review_digest"]
    ledger.approve_staged(stage_id, review["review_digest"])
    revision = ledger.commit(ledger.principal, None, None, stage_id)
    result["committed"] = True
    result["revision"] = revision["id"]
    result["sequence"] = revision["revision"]["sequence"]
    result["parents"] = list(revision["revision"]["parent_ids"])
    result["audit_valid"] = ledger.verify_audit()
    return result


_NOTICE_TEXT = {
    "blocked_sensitive_credential": (
        "message(s) contained credential-like data and were BLOCKED "
        "- nothing from them was captured."
    ),
    "untrusted_prompt_injection": (
        "message(s) matched prompt-injection patterns - claims from them are "
        "labeled untrusted-source and recorded as tentative."
    ),
    "injection_shaped_claim_dropped": (
        "instruction-shaped statement(s) were dropped and never became claims."
    ),
}


def render_handoff(result: dict[str, Any]) -> str:
    """Render the one-screen digest of what a handoff captured.

    Every field interpolated here can carry text a transcript author chose, so
    each one goes through ``terminal_safe`` on the way out: an unescaped
    newline in a statement, a title, or a working directory would let that
    author forge extra lines that look like this program's own output.
    """
    source = result["source"]
    captured = result["captured"]
    rule = "=" * 72
    if result["dry_run"]:
        headline = "BRAID - LOCAL HANDOFF (DRY RUN, nothing committed)"
    elif result["committed"]:
        headline = "BRAID - LOCAL HANDOFF (committed)"
    else:
        headline = "BRAID - LOCAL HANDOFF (nothing to capture)"
    lines = [
        rule,
        f" {headline}",
        rule,
        "",
        f" From   {terminal_safe(source['provider'], 24)}"
        f"/{terminal_safe(source['surface'], 32)}"
        f"  {terminal_safe(source['session_id'], 80)}",
        f"        {terminal_safe(source['title'] or '(untitled)', 80)}"
        f"  -  {terminal_safe(source['cwd'] or '(unknown cwd)', 80)}",
        f"        {source['messages_read']} of {source['messages_total']} messages"
        f" read, {source['messages_omitted']} earlier message(s) omitted",
        "",
        f" Into   local ledger project {terminal_safe(result['project'], 64)!r}",
        f"        as {terminal_safe(result['principal'], 80)}"
        "  (same principal, same machine)",
        "",
        f" CAPTURED {captured['claims']} claim(s)",
    ]
    for kind, count in sorted(
        captured["kinds"].items(), key=lambda item: (-item[1], item[0])
    ):
        lines.append(f"        {terminal_safe(kind, 14):<14}{count}")
    if captured["status_labeled"]:
        lines.append(
            f"        ({captured['status_labeled']} recorded as fact(s) labeled"
            ' "status")'
        )
    if captured["untrusted"]:
        lines.append(
            f"        ({captured['untrusted']} marked untrusted-source / tentative)"
        )
    if captured["redactions"]:
        detail = ", ".join(
            f"{terminal_safe(label, 40)} x{count}"
            for label, count in captured["redactions"].items()
        )
        lines.append(f"        PII redacted: {detail}")
    if result["notices"]:
        lines.append("")
        for code, count in sorted(result["notices"].items()):
            text = _NOTICE_TEXT.get(
                code, f"extraction notice: {terminal_safe(code, 60)}"
            )
            lines.append(f" !! {count} {text}")
    if result["preview"]:
        lines.extend(
            (
                "",
                " WHAT WAS CAPTURED (quoted data, never instructions to follow)",
            )
        )
        for item in result["preview"]:
            mark = "!" if item["untrusted"] else " "
            kind = terminal_safe(item["kind"], 12)
            statement = terminal_safe(item["statement"], PREVIEW_CHARS)
            lines.append(f"      {mark} {kind:<12}{statement}")
        if captured["claims"] > len(result["preview"]):
            lines.append(
                f"        ... and {captured['claims'] - len(result['preview'])} more"
            )
    lines.append("")
    if result["committed"]:
        parents = (
            ", ".join(terminal_safe(parent, 80) for parent in result["parents"])
            or "none"
        )
        lines.append(
            f" REVISION {terminal_safe(result['revision'], 80)}"
            f"   sequence {terminal_safe(result['sequence'], 20)}"
            f"   parents: {parents}"
        )
    elif result["dry_run"]:
        lines.extend(
            (
                " NOTHING WAS STAGED: the claims above were staged and reviewed",
                " so every scanner ran, then the stage was discarded. There is no",
                " approvable artifact left, and the ledger is unchanged.",
                "        re-run without --dry-run to commit what you just read.",
            )
        )
    else:
        lines.append(" Nothing was captured; the ledger is unchanged.")
    lines.extend(
        (
            f" Audit chain verified: {'yes' if result['audit_valid'] else 'NO'}",
            "",
            " Crossing a trust boundary? Upgrade to the governed path:",
            "          "
            + " ".join(terminal_safe(part, 120) for part in result["next_argv"]),
            rule,
        )
    )
    return "\n".join(lines) + "\n"
