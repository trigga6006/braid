"""Durable, local-only context ledger storage.

The ledger deliberately has no network client.  Import/export accepts only local
files, and untrusted imports are quarantined until explicitly accepted.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import time
from typing import Any, Iterator

from context_model import (
    canonical_json,
    create_revision,
    digest,
    plan_merge,
    resolved_active_view,
    semantic_diff,
    validate_claim,
    validate_revision,
)
from context_policy import plan_disclosure
from context_security import (
    SecurityError,
    create_disclosure_grant,
    digest as security_digest,
    identity_principal,
    load_or_create_identity,
    redact_sensitive,
    scan_sensitive,
    sign_export,
    strict_json_loads,
    verify_disclosure_grant,
    verify_export,
)


LEDGER_FORMAT = "braid-context-ledger/v1"
DISCLOSURE_FORMAT = "context-disclosure/v1"
MAX_IMPORT_BYTES = 2_000_000
AUDIT_TRANSITION_ACTIONS = frozenset(
    {
        "accept-import",
        "approve-stage",
        "commit",
        "disclose",
        "quarantine",
        "reconcile",
        "review-import",
        "revoke",
        "stage",
    }
)
AUDIT_STANDALONE_ACTIONS = frozenset({"review-stage"})
# Appended (never deletes evidence) to resolve a single dangling prepare left by
# a crash mid-transition; it references the abandoned prepare's details digest.
AUDIT_RECOVER_ACTION = "recover"
AUDIT_ENTRY_FIELDS = frozenset({"at", "action", "details", "previous", "hash"})
AUDIT_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
AUDIT_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _safe_project(project: str) -> str:
    if (
        not project
        or len(project) > 200
        or any(x in project for x in ("/", "\\", "\0", ".."))
    ):
        raise ValueError("Project must be a short logical name, not a path.")
    return project


def _safe_principal(principal: str) -> str:
    if not principal or len(principal) > 512 or "\0" in principal:
        raise ValueError(
            "Principal must be a non-empty identifier of at most 512 characters."
        )
    return principal


def _read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _read_untrusted_json(path: Path) -> Any:
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_IMPORT_BYTES + 1)
    except OSError as error:
        raise ValueError("Unable to read import file.") from error
    if len(raw) > MAX_IMPORT_BYTES:
        raise ValueError("Import file exceeds the 2 MB safety limit.")
    try:
        return strict_json_loads(raw)
    except SecurityError as error:
        raise ValueError(f"Unsafe import: {error}") from error


def _replace_with_retry(source: str, target: Path) -> None:
    """os.replace that tolerates a transient Windows sharing violation.

    On Windows, ``os.replace`` over a file a concurrent reader has briefly open
    raises ``PermissionError``.  Lock-free read paths make that reachable during
    a writer's replace, so retry for a bounded window before giving up.
    """
    deadline = time.monotonic() + 5.0
    while True:
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if os.name != "nt" or time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical_json(value) + b"\n"
    fd, name = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _replace_with_retry(name, path)
        try:
            directory = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except (OSError, AttributeError):
            pass
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(name)


def _audit_details_valid(action: str, details: Any) -> bool:
    """Validate the closed audit schema without trusting a recomputed hash."""

    if not isinstance(details, dict):
        return False
    base_action = action.removeprefix("prepare-")
    schemas: dict[str, tuple[frozenset[str], dict[str, type]]] = {
        "stage": (
            frozenset({"stage_id", "claims", "reviewed", "digest"}),
            {"stage_id": str, "claims": int, "reviewed": bool, "digest": str},
        ),
        "review-stage": (
            frozenset({"stage_id", "claims", "digest"}),
            {"stage_id": str, "claims": int, "digest": str},
        ),
        "approve-stage": (
            frozenset({"stage_id", "claims", "digest"}),
            {"stage_id": str, "claims": int, "digest": str},
        ),
        "commit": (
            frozenset({"id", "stage_id", "parents"}),
            {"id": str, "stage_id": str, "parents": list},
        ),
        "reconcile": (
            frozenset({"token", "heads", "conflicts", "digest"}),
            {"token": str, "heads": list, "conflicts": int, "digest": str},
        ),
        "disclose": (
            frozenset({"recipient", "claims", "revision"}),
            {"recipient": str, "claims": list, "revision": str},
        ),
        "revoke": (
            frozenset({"claim", "reason"}),
            {"claim": str, "reason": str},
        ),
        "quarantine": (
            frozenset({"token", "revision", "author_key_id"}),
            {"token": str, "revision": str, "author_key_id": str},
        ),
        "review-import": (
            frozenset({"token", "claims"}),
            {"token": str, "claims": int},
        ),
        "accept-import": (
            frozenset({"token", "revision"}),
            {"token": str, "revision": str},
        ),
        "recover": (
            frozenset({"recovered_action", "digest"}),
            {"recovered_action": str, "digest": str},
        ),
    }
    schema = schemas.get(base_action)
    if schema is None or frozenset(details) != schema[0]:
        return False
    for field, expected_type in schema[1].items():
        value = details[field]
        if type(value) is not expected_type:
            return False
        if expected_type is str and (not value or len(value) > 1_000):
            return False
        if expected_type is int and (value < 0 or value > 1_000_000):
            return False
        if expected_type is list and (
            len(value) > 500
            or any(
                not isinstance(item, str) or not item or len(item) > 1_000
                for item in value
            )
        ):
            return False
    if "digest" in details and not AUDIT_DIGEST.fullmatch(details["digest"]):
        return False
    return True


@contextlib.contextmanager
def _lock(path: Path) -> Iterator[None]:
    """Exclusive advisory lock that works for independent CLI processes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "a+b")
    try:
        if os.name == "nt":
            import msvcrt

            # Only seed the placeholder byte once; appending on every acquisition
            # would grow the lock file without bound.
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            while True:
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.05)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


class ContextLedger:
    def __init__(
        self,
        project: str,
        home: Path | None = None,
        principal: str | None = None,
    ) -> None:
        project = _safe_project(project)
        base = (
            home or Path(os.environ.get("BRAID_HOME", Path.home() / ".braid"))
        ).expanduser()
        self.project = project
        self.recipient_identity_path = base / "recipient-identity.json"
        recipient_identity = load_or_create_identity(self.recipient_identity_path)
        self.principal = identity_principal(recipient_identity)
        if principal is not None and _safe_principal(principal) != self.principal:
            raise ValueError(
                "Configured principal does not match this endpoint's recipient key."
            )
        self.pack_id = "p-" + hashlib.sha256(project.encode()).hexdigest()[:24]
        self.root = (
            base
            / "context-ledger"
            / "projects"
            / hashlib.sha256(project.encode()).hexdigest()[:24]
        )
        self.commits = self.root / "commits"
        self.quarantine = self.root / "quarantine"
        self.staging = self.root / "staging"
        self.reconciliations = self.root / "reconciliations"
        self.state_path = self.root / "state.json"
        # Kept only for one-time migration from versions before concurrent stages.
        self.staging_path = self.root / "staging.json"
        self.audit_path = self.root / "audit.jsonl"
        self.lock_path = self.root / ".lock"
        self.identity_path = self.root / "identity.json"
        self.root.mkdir(parents=True, exist_ok=True)
        if not self.state_path.exists():
            _atomic_json(
                self.state_path,
                {
                    "format": LEDGER_FORMAT,
                    "project": project,
                    "principal": self.principal,
                    "principal_key_id": recipient_identity.key_id,
                    "heads": [],
                    "sequence": 0,
                    "outbound": {},
                    "revoked": {},
                    "trusted_keys": {},
                    "remote_policies": {},
                    "policy_version": 1,
                },
            )
        with _lock(self.lock_path):
            state = _read_json(self.state_path)
            if not isinstance(state, dict):
                raise ValueError("Invalid ledger state.")
            configured = state.get("principal")
            bound_key = state.get("principal_key_id")
            if bound_key is None:
                if configured and configured != self.principal:
                    state["legacy_principal"] = configured
                state["principal"] = self.principal
                state["principal_key_id"] = recipient_identity.key_id
                _atomic_json(self.state_path, state)
            elif configured != self.principal or bound_key != recipient_identity.key_id:
                raise ValueError(
                    "Ledger recipient identity does not match this endpoint key."
                )
            if self.staging_path.exists():
                legacy = _read_json(self.staging_path)
                if isinstance(legacy, dict):
                    legacy.setdefault("format", "context-stage/v1")
                    legacy.setdefault("reviewed", False)
                    legacy.setdefault("stage_id", "s-legacy")
                    _atomic_json(self.staging / "s-legacy.json", legacy)
                self.staging_path.unlink(missing_ok=True)
            # Recover a ledger left with a single dangling prepare by a crash
            # mid-transition so it is not permanently bricked for all writes.
            self._heal_audit_unlocked()

    def _state(self) -> dict[str, Any]:
        state = _read_json(self.state_path)
        if (
            not isinstance(state, dict)
            or state.get("format") != LEDGER_FORMAT
            or state.get("project") != self.project
            or state.get("principal") != self.principal
            or state.get("principal_key_id") != self.principal.removeprefix("ed25519:")
        ):
            raise ValueError("Invalid ledger state.")
        state.setdefault("trusted_keys", {})
        state.setdefault("remote_policies", {})
        state.setdefault("policy_version", 1)
        state.setdefault("outbound", {})
        state.setdefault("revoked", {})
        return state

    def _audit(self, action: str, details: dict[str, Any]) -> None:
        previous = ""
        if self.audit_path.exists():
            lines = self.audit_path.read_text(encoding="utf-8").splitlines()
            if lines:
                try:
                    previous = str(json.loads(lines[-1]).get("hash", ""))
                except (json.JSONDecodeError, AttributeError) as error:
                    raise ValueError(
                        "Audit chain is malformed; refusing to append."
                    ) from error
        entry = {
            "at": _now(),
            "action": action,
            "details": details,
            "previous": previous,
        }
        entry["hash"] = digest(entry)
        with open(self.audit_path, "ab") as handle:
            handle.write(canonical_json(entry) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())

    @staticmethod
    def _verify_lines(lines: list[str]) -> bool:
        previous = ""
        pending: list[tuple[str, str]] = []
        try:
            for line in lines:
                entry = strict_json_loads(line, allowed_fields=set(AUDIT_ENTRY_FIELDS))
                if (
                    not isinstance(entry, dict)
                    or frozenset(entry) != AUDIT_ENTRY_FIELDS
                ):
                    return False
                action = entry.get("action")
                details = entry.get("details")
                at = entry.get("at")
                actual = entry.get("hash")
                prior = entry.get("previous")
                if (
                    not isinstance(action, str)
                    or action
                    not in (
                        AUDIT_TRANSITION_ACTIONS
                        | AUDIT_STANDALONE_ACTIONS
                        | {AUDIT_RECOVER_ACTION}
                        | {"prepare-" + item for item in AUDIT_TRANSITION_ACTIONS}
                    )
                    or not isinstance(at, str)
                    or not AUDIT_TIMESTAMP.fullmatch(at)
                    or not isinstance(actual, str)
                    or not AUDIT_DIGEST.fullmatch(actual)
                    or not isinstance(prior, str)
                    or (prior != "" and not AUDIT_DIGEST.fullmatch(prior))
                    or not _audit_details_valid(action, details)
                ):
                    return False
                actual = entry.pop("hash", None)
                if entry.get("previous") != previous or actual != digest(entry):
                    return False
                previous = actual
                details_digest = digest(details)
                if action.startswith("prepare-"):
                    pending.append((action.removeprefix("prepare-"), details_digest))
                elif action == AUDIT_RECOVER_ACTION:
                    reference = (details["recovered_action"], details["digest"])
                    if reference not in pending:
                        return False
                    pending.remove(reference)
                elif action in AUDIT_TRANSITION_ACTIONS:
                    if (action, details_digest) not in pending:
                        return False
                    pending.remove((action, details_digest))
            return not pending
        except (OSError, SecurityError, json.JSONDecodeError, TypeError, ValueError):
            return False

    def _verify_audit_unlocked(self) -> bool:
        if not self.audit_path.exists():
            return True
        try:
            lines = self.audit_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return False
        return self._verify_lines(lines)

    def _prepared_transition_touched_state(
        self, action: str, details: dict[str, Any]
    ) -> bool:
        """Return true when a prepared transition may have changed durable state.

        Recovery is allowed only for an intent that provably stopped before its
        first durable effect.  Ambiguity fails closed: appending ``recover`` to a
        partially or fully applied mutation would make the audit claim validity
        without a terminal record for the visible state change.
        """

        try:
            if action == "stage":
                return (self.staging / f"{details['stage_id']}.json").exists()
            if action == "approve-stage":
                staged = _read_json(self.staging / f"{details['stage_id']}.json")
                return isinstance(staged, dict) and (
                    staged.get("reviewed") is True
                    or staged.get("approved_digest") == details.get("digest")
                )
            if action == "commit":
                revision_id = str(details["id"])
                state = self._state()
                return (
                    self.commits / f"{revision_id}.json"
                ).exists() or revision_id in state["heads"]
            if action == "reconcile":
                return (self.reconciliations / f"{details['token']}.json").exists()
            if action == "quarantine":
                return (self.quarantine / f"{details['token']}.json").exists()
            if action == "review-import":
                item = _read_json(self.quarantine / f"{details['token']}.json")
                return isinstance(item, dict) and (
                    bool(item.get("reviewed_at"))
                    or item.get("reviewed_digest") is not None
                )
            if action == "revoke":
                return str(details["claim"]) in self._state()["revoked"]
            # An export can write its caller-selected output before recording
            # disclosure state, and accept-import can touch a pre-existing commit
            # plus several state fields. Their prepared details are insufficient
            # to prove that no durable effect occurred, so never auto-heal them.
            if action in {"disclose", "accept-import"}:
                return True
        except (KeyError, OSError, TypeError, ValueError):
            return True
        return True

    def _heal_audit_unlocked(self) -> None:
        """Recover from a crash mid-transition without weakening tamper-evidence.

        A power loss or ``kill -9`` immediately after a durable
        ``prepare-<action>`` entry can leave exactly one trailing, unmatched
        prepare. Rather than delete evidence, append a hash-chained ``recover``
        record only when action-specific durable state proves the mutation never
        began. If any effect is visible or ambiguous, leave the audit invalid so
        partially or fully applied state cannot be certified without its matching
        terminal marker.
        """
        if not self.audit_path.exists():
            return
        try:
            lines = self.audit_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        if not lines or self._verify_lines(lines):
            return
        try:
            last = strict_json_loads(lines[-1], allowed_fields=set(AUDIT_ENTRY_FIELDS))
        except (SecurityError, ValueError):
            return
        if (
            not isinstance(last, dict)
            or not isinstance(last.get("action"), str)
            or not last["action"].startswith("prepare-")
            or not isinstance(last.get("details"), dict)
        ):
            return
        recovered_action = last["action"].removeprefix("prepare-")
        if self._prepared_transition_touched_state(recovered_action, last["details"]):
            return
        entry = {
            "at": _now(),
            "action": AUDIT_RECOVER_ACTION,
            "details": {
                "recovered_action": recovered_action,
                "digest": digest(last["details"]),
            },
            "previous": str(last.get("hash", "")),
        }
        entry["hash"] = digest(entry)
        serialized = canonical_json(entry).decode("utf-8")
        # Commit the recovery only if it yields a fully valid chain: this proves
        # the sole defect was the single trailing dangling prepare.
        if not self._verify_lines(lines + [serialized]):
            return
        with open(self.audit_path, "ab") as handle:
            handle.write(canonical_json(entry) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())

    def verify_audit(self) -> bool:
        with _lock(self.lock_path):
            return self._verify_audit_unlocked()

    def _prepare_audit(self, action: str, details: dict[str, Any]) -> None:
        """Write a durable intent before a multi-file state transition."""
        if not self._verify_audit_unlocked():
            raise ValueError("Audit chain is invalid; refusing state mutation.")
        self._audit("prepare-" + action, details)

    def _stage_items(self) -> list[dict[str, Any]]:
        return [
            item
            for path in sorted(self.staging.glob("*.json"))
            if isinstance((item := _read_json(path)), dict)
        ]

    def _select_stage(self, stage_id: str | None) -> tuple[Path, dict[str, Any]]:
        if stage_id is not None:
            if not re.fullmatch(r"s-(?:[0-9a-f]{24}|legacy)", stage_id):
                raise ValueError("Invalid stage identifier.")
            path = self.staging / (stage_id + ".json")
            stage = _read_json(path)
            if not isinstance(stage, dict):
                raise ValueError("Unknown stage identifier.")
            return path, stage
        paths = sorted(self.staging.glob("*.json"))
        if not paths:
            raise ValueError("Nothing is staged.")
        if len(paths) > 1:
            raise ValueError("Multiple stages exist; choose one with --stage-id.")
        stage = _read_json(paths[0])
        if not isinstance(stage, dict):
            raise ValueError("Invalid staged context.")
        return paths[0], stage

    def stage(
        self,
        claims: list[dict[str, Any]],
        message: str = "",
        reconciliation_token: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(claims, list):
            raise ValueError("Claims must be a list.")
        if reconciliation_token is not None and not re.fullmatch(
            r"merge-[0-9a-f]{24}", reconciliation_token
        ):
            raise ValueError("Invalid reconciliation token.")
        for claim in claims:
            validate_claim(claim)
        findings = scan_sensitive(claims)
        if findings:
            raise ValueError(
                "Credential-like data cannot be staged; redact it before continuing."
            )
        with _lock(self.lock_path):
            stage_id = "s-" + secrets.token_hex(12)
            staged = {
                "format": "context-stage/v1",
                "stage_id": stage_id,
                "claims": claims,
                "message": message,
                "reconciliation_token": reconciliation_token,
                "reviewed": False,
                "reviewed_at": None,
                "approved_digest": None,
                "updated_at": _now(),
            }
            details = {
                "stage_id": stage_id,
                "claims": len(claims),
                "reviewed": False,
                "digest": digest(staged),
            }
            self._prepare_audit("stage", details)
            _atomic_json(self.staging / (stage_id + ".json"), staged)
            self._audit("stage", details)
            return staged

    def review_staged(self, stage_id: str) -> dict[str, Any]:
        with _lock(self.lock_path):
            _, staged = self._select_stage(stage_id)
            claims = staged.get("claims")
            if not isinstance(claims, list) or not claims:
                raise ValueError("Stage has no claims to review.")
            for claim in claims:
                validate_claim(claim)
            if scan_sensitive(claims):
                raise ValueError(
                    "Stage contains credential-like data and cannot be reviewed."
                )
            review_digest = self._stage_review_digest(staged)
            self._audit(
                "review-stage",
                {"stage_id": stage_id, "claims": len(claims), "digest": review_digest},
            )
            return {
                "stage_id": stage_id,
                "claim_count": len(claims),
                "claims": claims,
                "message": staged.get("message", ""),
                "reconciliation_token": staged.get("reconciliation_token"),
                "reviewed": staged.get("reviewed") is True,
                "review_digest": review_digest,
            }

    @staticmethod
    def _stage_review_digest(staged: dict[str, Any]) -> str:
        return digest(
            {
                "format": staged.get("format"),
                "stage_id": staged.get("stage_id"),
                "claims": staged.get("claims"),
                "message": staged.get("message", ""),
                "reconciliation_token": staged.get("reconciliation_token"),
            }
        )

    def approve_staged(self, stage_id: str, review_digest: str) -> dict[str, Any]:
        with _lock(self.lock_path):
            path, staged = self._select_stage(stage_id)
            current = self._stage_review_digest(staged)
            if not re.fullmatch(
                r"sha256:[0-9a-f]{64}", review_digest
            ) or not secrets.compare_digest(current, review_digest):
                raise PermissionError(
                    "Stage changed after review; inspect it again before approval."
                )
            staged["reviewed"] = True
            staged["reviewed_at"] = _now()
            staged["approved_digest"] = current
            details = {
                "stage_id": stage_id,
                "claims": len(staged["claims"]),
                "digest": current,
            }
            self._prepare_audit("approve-stage", details)
            _atomic_json(path, staged)
            self._audit("approve-stage", details)
            return {
                "stage_id": stage_id,
                "claims": len(staged["claims"]),
                "reviewed": True,
                "review_digest": current,
            }

    def status(self) -> dict[str, Any]:
        with _lock(self.lock_path):
            state = self._state()
            stages = self._stage_items()
            return {
                "project": self.project,
                "principal": self.principal,
                "pack_id": self.pack_id,
                "heads": state["heads"],
                "sequence": state["sequence"],
                "staged_claims": sum(len(item.get("claims", [])) for item in stages),
                "stages": [
                    {
                        "stage_id": item.get("stage_id"),
                        "claims": len(item.get("claims", [])),
                        "reviewed": item.get("reviewed") is True,
                    }
                    for item in stages
                ],
                "audit_valid": self._verify_audit_unlocked(),
                "revoked": sorted(state["revoked"]),
                "trusted_author_keys": sorted(state["trusted_keys"]),
                "policy_version": state["policy_version"],
                "quarantined": len(list(self.quarantine.glob("*.json"))),
            }

    def _revision(self, revision_id: str) -> dict[str, Any]:
        value = _read_json(self.commits / (revision_id + ".json"))
        if not isinstance(value, dict):
            raise ValueError("Unknown revision.")
        validate_revision(value)
        return value

    def _all_revisions(self) -> dict[str, dict[str, Any]]:
        return {
            path.stem: self._revision(path.stem) for path in self.commits.glob("*.json")
        }

    def _history(self, revision_id: str) -> list[dict[str, Any]]:
        known = self._all_revisions()
        ordered: list[dict[str, Any]] = []
        visiting: set[str] = set()
        seen: set[str] = set()

        def visit(current: str) -> None:
            if current in seen:
                return
            if current in visiting:
                raise ValueError("Revision graph contains a cycle.")
            revision = known.get(current)
            if revision is None:
                raise ValueError(f"Missing parent revision: {current}")
            visiting.add(current)
            for parent in revision["revision"]["parent_ids"]:
                visit(parent)
            visiting.remove(current)
            seen.add(current)
            ordered.append(revision)

        visit(revision_id)
        return ordered

    def commit(
        self,
        author: str,
        governance: dict[str, Any] | None = None,
        message: str | None = None,
        stage_id: str | None = None,
    ) -> dict[str, Any]:
        with _lock(self.lock_path):
            state = self._state()
            stage_path, stage = self._select_stage(stage_id)
            if not isinstance(stage, dict) or not stage.get("claims"):
                raise ValueError("Nothing is staged.")
            if stage.get("reviewed") is not True:
                raise PermissionError(
                    "Stage is not approved; run review-staged, then approve-staged."
                )
            if not secrets.compare_digest(
                str(stage.get("approved_digest", "")),
                self._stage_review_digest(stage),
            ):
                raise PermissionError(
                    "Stage changed after approval; review and approve it again."
                )
            if len(state["heads"]) > 2:
                raise ValueError(
                    "More than two heads require explicit pairwise reconciliation before commit."
                )
            reconciliation_path: Path | None = None
            if len(state["heads"]) == 2:
                token = stage.get("reconciliation_token")
                if not isinstance(token, str) or not re.fullmatch(
                    r"merge-[0-9a-f]{24}", token
                ):
                    raise PermissionError(
                        "Two heads require reconcile and an explicit resolution stage."
                    )
                reconciliation_path = self.reconciliations / (token + ".json")
                reconciliation = _read_json(reconciliation_path)
                if not isinstance(reconciliation, dict) or sorted(
                    reconciliation.get("heads", [])
                ) != sorted(state["heads"]):
                    raise PermissionError(
                        "Reconciliation token is missing, stale, or for different heads."
                    )
                unresolved = []
                for conflict in reconciliation.get("plan", {}).get("conflicts", []):
                    conflict_ids = {
                        claim["id"]
                        for side in ("local_claims", "remote_claims")
                        for claim in conflict.get(side, [])
                    }
                    resolved = any(
                        claim.get("semantic_key") == conflict.get("semantic_key")
                        and (
                            claim.get("kind") == "disagreement"
                            or conflict_ids.issubset(set(claim.get("supersedes", [])))
                        )
                        for claim in stage["claims"]
                    )
                    if not resolved:
                        unresolved.append(str(conflict.get("semantic_key", "")))
                if unresolved:
                    raise PermissionError(
                        "Resolution stage must preserve or explicitly supersede conflicts: "
                        + ", ".join(sorted(unresolved))
                    )
            elif stage.get("reconciliation_token"):
                raise PermissionError(
                    "Reconciliation token does not match a two-head merge."
                )
            known = self._all_revisions()
            sequence = (
                max(
                    [
                        int(state["sequence"]),
                        *[
                            int(known[head]["revision"]["sequence"])
                            for head in state["heads"]
                        ],
                    ]
                )
                + 1
            )
            revision_id = "r-" + secrets.token_hex(12)
            authors = [
                {"principal_id": author, "display_name": author, "role": "owner"}
            ]
            default_governance = {
                "owner_principal_id": author,
                "visibility": "private",
                "share_policy": "owner_approval",
                "recipients": [],
            }
            effective_governance = {**default_governance, **(governance or {})}
            commit_message = (
                message if message is not None else str(stage.get("message", ""))
            )
            revision = create_revision(
                self.pack_id,
                revision_id,
                sequence,
                list(state["heads"]),
                stage["claims"],
                authors,
                effective_governance,
                commit_message.strip() or "Context ledger commit",
            )
            validate_revision(revision, known)
            revision_id = revision["id"]
            details = {
                "id": revision_id,
                "stage_id": stage.get("stage_id"),
                "parents": revision["revision"]["parent_ids"],
            }
            self._prepare_audit("commit", details)
            _atomic_json(self.commits / (revision_id + ".json"), revision)
            state["heads"] = [revision_id]
            state["sequence"] = sequence
            _atomic_json(self.state_path, state)
            stage_path.unlink(missing_ok=True)
            if reconciliation_path is not None:
                reconciliation_path.unlink(missing_ok=True)
            self._audit("commit", details)
            return revision

    def show(self, revision_id: str) -> dict[str, Any]:
        with _lock(self.lock_path):
            return self._revision(revision_id)

    def log(self) -> list[dict[str, Any]]:
        with _lock(self.lock_path):
            return sorted(
                self.current_history(),
                key=lambda item: (int(item["revision"]["sequence"]), item["id"]),
                reverse=True,
            )

    def diff(self, before: str, after: str) -> dict[str, Any]:
        with _lock(self.lock_path):
            return semantic_diff(self._history(before), self._history(after))

    def current_history(self) -> list[dict[str, Any]]:
        heads = self._state()["heads"]
        combined: dict[str, dict[str, Any]] = {}
        for head in heads:
            for revision in self._history(head):
                combined[revision["id"]] = revision
        return sorted(
            combined.values(),
            key=lambda item: (int(item["revision"]["sequence"]), item["id"]),
        )

    def active_claims_at(
        self, revision_id: str, now: str | None = None
    ) -> list[dict[str, Any]]:
        """Active claims as of one revision, as a disclosure from it would see.

        Distinct from `freshness`, which resolves the *current* heads. A caller
        deciding whether a disclosure from `revision_id` is permitted must look
        at that revision, since a later commit can change the current view
        without changing what this disclosure will carry.
        """
        with _lock(self.lock_path):
            return resolved_active_view(self._history(revision_id), now)[
                "active_claims"
            ]

    def freshness(self, now: str | None = None) -> dict[str, Any]:
        with _lock(self.lock_path):
            view = resolved_active_view(self.current_history(), now)
            revoked = self._state()["revoked"]
            kept, historical = [], list(view["historical_claims"])
            for claim in view["active_claims"]:
                if claim["id"] in revoked:
                    item = dict(claim)
                    item["effective_status"] = "revoked"
                    item["revocation"] = revoked[claim["id"]]
                    historical.append(item)
                else:
                    kept.append(claim)
            view["active_claims"] = kept
            view["historical_claims"] = sorted(historical, key=lambda item: item["id"])
            return view

    def conflicts(self) -> dict[str, Any]:
        """Return a read-only conflict view for the current pair of heads."""
        with _lock(self.lock_path):
            heads = list(self._state()["heads"])
            if len(heads) != 2:
                return {
                    "heads": heads,
                    "auto_claims": [],
                    "conflicts": [],
                    "mergeable": True,
                }
            return {
                "heads": heads,
                **plan_merge(self._history(heads[0]), self._history(heads[1])),
            }

    def plan(
        self, recipient_profile: dict[str, Any], claim_ids: list[str] | None = None
    ) -> dict[str, Any]:
        with _lock(self.lock_path):
            state = self._state()
            return plan_disclosure(
                self.current_history(),
                recipient_profile,
                revoked_claim_ids=state["revoked"],
                required_claim_ids=claim_ids or [],
            )

    def prepare_reconciliation(
        self, local_ids: list[str], remote_ids: list[str]
    ) -> dict[str, Any]:
        with _lock(self.lock_path):
            heads = list(self._state()["heads"])
            if len(heads) != 2:
                raise ValueError("Reconciliation requires exactly two current heads.")
            if not local_ids or not remote_ids or set(local_ids) & set(remote_ids):
                raise ValueError(
                    "Local and remote reconciliation sides must be non-empty and disjoint."
                )
            if set(local_ids + remote_ids) != set(heads):
                raise ValueError(
                    "Reconciliation sides must exactly match the two current heads."
                )
            local_history: dict[str, dict[str, Any]] = {}
            remote_history: dict[str, dict[str, Any]] = {}
            for revision_id in local_ids:
                for revision in self._history(revision_id):
                    local_history[revision["id"]] = revision
            for revision_id in remote_ids:
                for revision in self._history(revision_id):
                    remote_history[revision["id"]] = revision
            plan = plan_merge(local_history.values(), remote_history.values())
            token = "merge-" + secrets.token_hex(12)
            record = {
                "format": "context-reconciliation/v1",
                "token": token,
                "heads": sorted(heads),
                "local": list(local_ids),
                "remote": list(remote_ids),
                "plan": plan,
                "created_at": _now(),
            }
            details = {
                "token": token,
                "heads": sorted(heads),
                "conflicts": len(plan["conflicts"]),
                "digest": digest(record),
            }
            self._prepare_audit("reconcile", details)
            _atomic_json(self.reconciliations / (token + ".json"), record)
            self._audit("reconcile", details)
            return {"reconciliation_token": token, **plan}

    @staticmethod
    def _policy_digest(governance: dict[str, Any]) -> str:
        return hashlib.sha256(canonical_json(governance)).hexdigest()

    def _signed_bundle(
        self,
        recipient: str,
        revision_id: str,
        claim_ids: list[str] | None = None,
        purpose: str = "Context reconciliation",
        max_sensitivity: str = "internal",
        expires_seconds: int = 86_400,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        source = self._revision(revision_id)
        plan = plan_disclosure(
            self._history(revision_id),
            {
                "principal_id": recipient,
                "purpose": purpose,
                "max_sensitivity": max_sensitivity,
                "max_claims": 500,
                "max_bytes": 900_000,
            },
            revoked_claim_ids=self._state()["revoked"],
            required_claim_ids=claim_ids or [],
        )
        if claim_ids is not None:
            wanted = set(claim_ids)
            plan["claims"] = [
                claim for claim in plan["claims"] if claim["id"] in wanted
            ]
            plan["included"] = [
                item for item in plan["included"] if item["claim_id"] in wanted
            ]
        if not plan["claims"]:
            raise PermissionError("Disclosure policy selected no claims.")
        if scan_sensitive(plan["claims"]):
            raise PermissionError(
                "Disclosure contains credential-like data; redact it before sharing."
            )
        identity = load_or_create_identity(self.identity_path)
        now = int(time.time())
        export_id = "x-" + secrets.token_hex(12)
        governance = {
            "owner_principal_id": identity.key_id,
            "visibility": "scoped",
            "share_policy": "owner_approval",
            "recipients": [recipient],
        }
        disclosed = create_revision(
            source["pack_id"],
            export_id,
            1,
            [],
            plan["claims"],
            [
                {
                    "principal_id": identity.key_id,
                    "display_name": "Local Braid identity",
                    "role": "owner",
                }
            ],
            governance,
            f"Recipient-minimized disclosure for {purpose}",
            scope={
                "id": source["scope"]["id"],
                "purpose": purpose,
                "project": source["scope"].get("project", ""),
            },
            artifacts=[
                {
                    "id": "source-revision",
                    "media_type": "application/vnd.braid.context-pack+json",
                    "uri": "braid:" + source["id"],
                    "digest": source["integrity"]["canonical_sha256"],
                }
            ],
        )
        policy_digest = self._policy_digest(governance)
        policy_version = int(self._state()["policy_version"])
        signed = sign_export(
            disclosed,
            identity,
            project=self.pack_id,
            scope=source["scope"]["id"],
            recipient=recipient,
            policy_digest=policy_digest,
            policy_version=policy_version,
            expires_at=now + expires_seconds,
            parents=[source["integrity"]["canonical_sha256"].removeprefix("sha256:")],
        )
        grant = create_disclosure_grant(
            identity,
            pack_digest=security_digest(disclosed),
            project=self.pack_id,
            scope=source["scope"]["id"],
            recipient=recipient,
            policy_digest=policy_digest,
            policy_version=policy_version,
            expires_at=now + expires_seconds,
        )
        return {"format": DISCLOSURE_FORMAT, "export": signed, "grant": grant}, plan

    def disclose(
        self,
        recipient: str,
        revision_id: str,
        claim_ids: list[str] | None = None,
        purpose: str = "Context reconciliation",
        max_sensitivity: str = "internal",
    ) -> dict[str, Any]:
        if not recipient or len(recipient) > 200:
            raise ValueError("Invalid recipient.")
        with _lock(self.lock_path):
            state, revision = self._state(), self._revision(revision_id)
            policy = revision.get("governance", {})
            allowed = policy.get("recipients") if isinstance(policy, dict) else []
            if policy.get("share_policy") == "deny" or (
                allowed and recipient not in allowed
            ):
                raise PermissionError("Revision policy does not permit this recipient.")
            bundle, plan = self._signed_bundle(
                recipient, revision_id, claim_ids, purpose, max_sensitivity
            )
            ids = [claim["id"] for claim in bundle["export"]["revision"]["claims"]]
            result = {
                "recipient": recipient,
                "revision": revision_id,
                "claim_ids": ids,
                "plan": plan,
                "bundle": bundle,
            }
            self._prepare_audit(
                "disclose",
                {
                    "recipient": recipient,
                    "claims": sorted(ids),
                    "revision": revision_id,
                },
            )
            self._record_disclosure(state, result)
            return result

    def _record_disclosure(self, state: dict[str, Any], result: dict[str, Any]) -> None:
        recipient = str(result["recipient"])
        revision_id = str(result["revision"])
        ledger = state["outbound"].setdefault(recipient, {})
        for claim_id in result["claim_ids"]:
            if claim_id in state["revoked"]:
                raise PermissionError("A selected claim has been revoked.")
            ledger[claim_id] = {"revision": revision_id, "disclosed_at": _now()}
        _atomic_json(self.state_path, state)
        self._audit(
            "disclose",
            {
                "recipient": recipient,
                "claims": sorted(result["claim_ids"]),
                "revision": revision_id,
            },
        )

    def who_has_claim(self, claim_id: str) -> list[str]:
        return sorted(
            recipient
            for recipient, items in self._state()["outbound"].items()
            if claim_id in items
        )

    def revoke(self, claim_id: str, reason: str) -> None:
        if not reason.strip() or len(reason) > 500:
            raise ValueError("Revocation reason must be 1 to 500 characters.")
        with _lock(self.lock_path):
            if not any(
                claim["id"] == claim_id
                for revision in self.current_history()
                for claim in revision["claims"]
            ):
                raise ValueError("Cannot revoke an unknown claim.")
            state = self._state()
            state["revoked"][claim_id] = {"reason": reason.strip(), "at": _now()}
            details = {"claim": claim_id, "reason": reason.strip()}
            self._prepare_audit("revoke", details)
            _atomic_json(self.state_path, state)
            self._audit("revoke", details)

    def export(
        self,
        revision_id: str,
        output: Path,
        recipient: str,
        claim_ids: list[str] | None = None,
        purpose: str = "Context reconciliation",
        max_sensitivity: str = "internal",
    ) -> dict[str, Any]:
        if "://" in str(output):
            raise ValueError("Exports require a local path.")
        with _lock(self.lock_path):
            state, revision = self._state(), self._revision(revision_id)
            policy = revision.get("governance", {})
            allowed = policy.get("recipients") if isinstance(policy, dict) else []
            if policy.get("share_policy") == "deny" or (
                allowed and recipient not in allowed
            ):
                raise PermissionError("Revision policy does not permit this recipient.")
            bundle, plan = self._signed_bundle(
                recipient, revision_id, claim_ids, purpose, max_sensitivity
            )
            result = {
                "recipient": recipient,
                "revision": revision_id,
                "claim_ids": [
                    claim["id"] for claim in bundle["export"]["revision"]["claims"]
                ],
                "plan": plan,
                "bundle": bundle,
            }
            self._prepare_audit(
                "disclose",
                {
                    "recipient": recipient,
                    "claims": sorted(result["claim_ids"]),
                    "revision": revision_id,
                },
            )
            _atomic_json(output.expanduser(), bundle)
            self._record_disclosure(state, result)
            return {key: result[key] for key in ("recipient", "revision", "claim_ids")}

    def _verify_incoming_bundle(
        self, bundle: dict[str, Any]
    ) -> tuple[Any, dict[str, Any], dict[str, Any], dict[str, Any]]:
        if bundle.get("format") != DISCLOSURE_FORMAT:
            raise ValueError("Unsupported signed disclosure format.")
        signed, grant = bundle.get("export"), bundle.get("grant")
        if not isinstance(signed, dict) or not isinstance(grant, dict):
            raise ValueError("Invalid signed disclosure bundle.")
        quarantined = verify_export(signed, recipient=self.principal)
        revision = dict(quarantined.export["revision"])
        validate_revision(revision)
        # The legitimate protocol always emits a parentless, sequence-1 root
        # disclosure.  A revision that names a local head as its parent would be
        # accepted as a higher-sequence descendant and silently supersede local
        # claims in the resolved view; require an independent root so any real
        # divergence must go through explicit two-head reconciliation.
        if revision["revision"]["parent_ids"]:
            raise SecurityError(
                "A signed disclosure must be an independent root revision."
            )
        verify_disclosure_grant(
            grant,
            pack_digest=security_digest(revision),
            project=str(signed["project"]),
            scope=str(signed["scope"]),
            recipient=self.principal,
            policy_digest=str(signed["policy_digest"]),
            min_policy_version=int(signed["policy_version"]),
            expected_issuer_key_id=str(signed["author_key_id"]),
        )
        if grant.get("issuer_public_key") != signed.get("author_public_key"):
            raise SecurityError("disclosure grant issuer does not match export author")
        return quarantined, revision, signed, grant

    @staticmethod
    def _incoming_review(
        quarantined: Any, revision: dict[str, Any], signed: dict[str, Any]
    ) -> dict[str, Any]:
        redacted_revision, security_findings = redact_sensitive(revision)
        return {
            "author_key_id": quarantined.author_key_id,
            "recipient": signed["recipient"],
            "project": signed["project"],
            "scope": signed["scope"],
            "claim_count": len(revision["claims"]),
            "claims": [
                {
                    "id": claim["id"],
                    "kind": claim["kind"],
                    "statement": claim["statement"],
                    "semantic_key": claim["semantic_key"],
                    "confidence": claim["confidence"],
                    "sensitivity": claim.get("sensitivity", "internal"),
                    "supersedes": claim.get("supersedes", []),
                    "provenance": claim["provenance"],
                }
                for claim in redacted_revision["claims"]
            ],
            "parent_ids": list(revision["revision"]["parent_ids"]),
            "security_findings": security_findings,
        }

    def import_quarantine(self, source: Path) -> str:
        if "://" in str(source):
            raise ValueError("Imports require a local path.")
        raw = _read_untrusted_json(source.expanduser())
        if (
            isinstance(raw, dict)
            and raw.get("type") == "context-pack"
            and isinstance(raw.get("bundle"), dict)
        ):
            raw = raw["bundle"]
        elif isinstance(raw, dict) and isinstance(raw.get("events"), list):
            bundles = [
                event.get("bundle")
                for event in raw["events"]
                if isinstance(event, dict)
                and event.get("type") == "context-pack"
                and isinstance(event.get("bundle"), dict)
            ]
            if len(bundles) != 1:
                raise ValueError(
                    "Event file must contain exactly one signed context-pack event."
                )
            raw = bundles[0]
        if not isinstance(raw, dict) or raw.get("format") != DISCLOSURE_FORMAT:
            raise ValueError(
                "Unsigned or unsupported export; a signed context-disclosure/v1 bundle is required."
            )
        try:
            quarantined, revision, signed, _ = self._verify_incoming_bundle(raw)
        except (SecurityError, KeyError, TypeError, ValueError) as error:
            raise ValueError(f"Invalid signed disclosure: {error}") from error
        token = secrets.token_hex(12)
        review = self._incoming_review(quarantined, revision, signed)
        bundle_digest = security_digest(raw)
        record = {
            "source_name": source.name,
            "imported_at": _now(),
            "bundle": raw,
            "bundle_digest": bundle_digest,
            "reviewed_digest": None,
            "review": review,
        }
        details = {
            "token": token,
            "revision": revision["id"],
            "author_key_id": quarantined.author_key_id,
        }
        with _lock(self.lock_path):
            # Deduplicate a byte-identical pack already awaiting review so an
            # interrupted/retried publish does not create a second token for the
            # same content.
            for existing_path in self.quarantine.glob("*.json"):
                existing = _read_json(existing_path)
                if isinstance(existing, dict) and secrets.compare_digest(
                    str(existing.get("bundle_digest", "")), bundle_digest
                ):
                    return existing_path.stem
            self._prepare_audit("quarantine", details)
            _atomic_json(self.quarantine / (token + ".json"), record)
            self._audit("quarantine", details)
        return token

    def review_import(self, token: str) -> dict[str, Any]:
        with _lock(self.lock_path):
            if not re.fullmatch(r"[0-9a-f]{24}", token):
                raise ValueError("Invalid quarantine token.")
            path = self.quarantine / (token + ".json")
            item = _read_json(path)
            if not isinstance(item, dict):
                raise ValueError("Unknown quarantined import.")
            bundle = item.get("bundle")
            if not isinstance(bundle, dict):
                raise ValueError("Unknown quarantined import.")
            current_digest = security_digest(bundle)
            if not secrets.compare_digest(
                str(item.get("bundle_digest", "")), current_digest
            ):
                raise PermissionError(
                    "Quarantined bundle changed; import it again before review."
                )
            try:
                quarantined, revision, signed, _ = self._verify_incoming_bundle(bundle)
            except (SecurityError, KeyError, TypeError, ValueError) as error:
                raise PermissionError(
                    f"Quarantined bundle no longer verifies: {error}"
                ) from error
            review_payload = self._incoming_review(quarantined, revision, signed)
            item["reviewed_at"] = _now()
            item["reviewed_digest"] = current_digest
            item["review"] = review_payload
            details = {"token": token, "claims": len(revision["claims"])}
            self._prepare_audit("review-import", details)
            _atomic_json(path, item)
            review = {"token": token, **review_payload}
            self._audit("review-import", details)
            return review

    def accept_import(
        self, token: str, *, allow_sensitive: bool = False
    ) -> dict[str, Any]:
        with _lock(self.lock_path):
            if not re.fullmatch(r"[0-9a-f]{24}", token):
                raise ValueError("Invalid quarantine token.")
            item = _read_json(self.quarantine / (token + ".json"))
            bundle = item.get("bundle") if isinstance(item, dict) else None
            if not isinstance(bundle, dict):
                raise ValueError("Unknown quarantined import.")
            if not item.get("reviewed_at"):
                raise PermissionError(
                    "Review the quarantined claims before acceptance."
                )
            current_bundle_digest = security_digest(bundle)
            if not secrets.compare_digest(
                str(item.get("reviewed_digest", "")), current_bundle_digest
            ):
                raise PermissionError(
                    "Quarantined bundle changed after review; review it again."
                )
            quarantined, revision, signed, grant = self._verify_incoming_bundle(bundle)
            findings = scan_sensitive(revision)
            if findings and not allow_sensitive:
                raise PermissionError(
                    "Import contains credential-like data; acceptance requires explicit override."
                )
            # Only revisions reachable from accepted heads can satisfy ancestry.
            # An orphan file left by a crash or an older rejected import must
            # never become an implicit trust anchor for a later disclosure.
            known = {item["id"]: item for item in self.current_history()}
            validate_revision(revision, known)
            rid = revision["id"]
            existing = self.commits / (rid + ".json")
            if existing.exists() and canonical_json(
                self._revision(rid)
            ) != canonical_json(revision):
                raise ValueError("Revision identifier collision.")
            state = self._state()
            # Policy monotonicity is a per-authoring-key invariant: policy_digest
            # is derived from the sender's own governance, so two co-members
            # sharing a ledger-project name legitimately present different
            # digests.  Keying by project alone would flag the second peer as an
            # equivocation and permanently reject every peer but the first.
            project_key = str(signed["project"])
            policy_key = project_key + "\x1f" + quarantined.author_key_id
            remote = state["remote_policies"].get(policy_key)
            current_policy = (
                int(signed["policy_version"]),
                str(signed["policy_digest"]),
            )
            # A pre-migration project-wide baseline (bare-project key, no author)
            # still bars a rollback to a lower policy version for any author on
            # that project, so the upgrade cannot open a one-time downgrade.
            legacy_floor = state["remote_policies"].get(project_key)
            if (
                isinstance(legacy_floor, dict)
                and "version" in legacy_floor
                and current_policy[0] < int(legacy_floor["version"])
            ):
                raise PermissionError(
                    "Remote policy version is below the recorded project floor."
                )
            if remote and (
                current_policy[0] < int(remote["version"])
                or (
                    current_policy[0] == int(remote["version"])
                    and current_policy[1] != remote["digest"]
                )
            ):
                raise PermissionError(
                    "Remote policy rollback or equivocation detected."
                )
            public_key = str(signed["author_public_key"])
            trusted = state["trusted_keys"].get(quarantined.author_key_id)
            if trusted is not None and trusted != public_key:
                raise PermissionError("Trusted author key changed.")
            if rid not in state["heads"] and len(state["heads"]) >= 2:
                raise PermissionError(
                    "Ledger already has two heads; reconcile them before accepting another."
                )
            details = {"token": token, "revision": rid}
            self._prepare_audit("accept-import", details)
            # All rejectable checks happen before content is made durable.  A
            # state-write failure may leave an orphan file, but it is unreachable
            # from heads and therefore hidden from log/current views.
            _atomic_json(self.commits / (rid + ".json"), revision)
            state["trusted_keys"][quarantined.author_key_id] = public_key
            state["remote_policies"][policy_key] = {
                "version": current_policy[0],
                "digest": current_policy[1],
            }
            state["heads"] = sorted(set(state["heads"] + [rid]))
            state["sequence"] = max(
                int(state["sequence"]), int(revision["revision"]["sequence"])
            )
            _atomic_json(self.state_path, state)
            (self.quarantine / (token + ".json")).unlink(missing_ok=True)
            self._audit("accept-import", details)
            return revision
