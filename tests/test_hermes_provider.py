from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import braid_session as bridge  # noqa: E402


# The subset of Hermes' own schema that Braid discovery reads.  Kept literal so
# a drift in the columns Braid depends on fails here rather than in the field.
_HERMES_SCHEMA = """
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    model TEXT,
    started_at REAL NOT NULL,
    ended_at REAL,
    message_count INTEGER DEFAULT 0,
    cwd TEXT,
    git_branch TEXT,
    git_repo_root TEXT,
    title TEXT,
    archived INTEGER NOT NULL DEFAULT 0,
    pinned INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT,
    timestamp REAL NOT NULL
);
"""


def _build_store(home: Path, rows: list[dict], messages: list[tuple] = ()) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    database = home / "state.db"
    connection = sqlite3.connect(database)
    try:
        connection.executescript(_HERMES_SCHEMA)
        for row in rows:
            connection.execute(
                "INSERT INTO sessions (id, source, started_at, cwd, git_repo_root,"
                " title, archived) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    row["id"],
                    row.get("source", "cli"),
                    row.get("started_at", 1_700_000_000.0),
                    row.get("cwd"),
                    row.get("git_repo_root"),
                    row.get("title"),
                    row.get("archived", 0),
                ),
            )
        for session_id, timestamp in messages:
            connection.execute(
                "INSERT INTO messages (session_id, role, content, timestamp)"
                " VALUES (?, 'user', 'x', ?)",
                (session_id, timestamp),
            )
        connection.commit()
    finally:
        connection.close()
    return database


class HermesHomeTests(unittest.TestCase):
    def test_explicit_home_wins(self) -> None:
        with mock.patch.dict("os.environ", {"HERMES_HOME": "/custom/hermes"}):
            self.assertEqual(bridge.hermes_home(), Path("/custom/hermes"))

    def test_platform_default_matches_hermes_own_resolution(self) -> None:
        # Hermes is not always ~/.hermes: on Windows it is %LOCALAPPDATA%/hermes.
        with mock.patch.dict("os.environ", {"HERMES_HOME": ""}):
            with mock.patch.object(bridge.sys, "platform", "win32"):
                with mock.patch.dict(
                    "os.environ", {"LOCALAPPDATA": r"C:\Users\x\AppData\Local"}
                ):
                    self.assertEqual(
                        bridge.hermes_home(),
                        Path(r"C:\Users\x\AppData\Local") / "hermes",
                    )
            with mock.patch.object(bridge.sys, "platform", "linux"):
                self.assertEqual(bridge.hermes_home(), Path.home() / ".hermes")


class HermesDiscoveryTests(unittest.TestCase):
    def test_discovers_metadata_and_prefers_repo_root_and_last_message(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "hermes"
            _build_store(
                home,
                [
                    {
                        "id": "sess-a",
                        "source": "cli",
                        "started_at": 1_700_000_000.0,
                        "cwd": "/work/pkg/sub",
                        "git_repo_root": "/work/pkg",
                        "title": "Auth refactor",
                    }
                ],
                messages=[("sess-a", 1_700_009_999.0)],
            )
            with mock.patch.dict("os.environ", {"HERMES_HOME": str(home)}):
                sessions = bridge.discover_hermes()
        self.assertEqual(len(sessions), 1)
        session = sessions[0]
        self.assertEqual(session.provider, "hermes")
        self.assertEqual(session.surface, "hermes-cli")
        self.assertEqual(session.resume_id, "sess-a")
        # git_repo_root is the coarser workspace identity, so it wins over cwd.
        self.assertEqual(session.cwd, "/work/pkg")
        # last_active comes from the newest message, not started_at.
        self.assertEqual(session.updated, 1_700_009_999.0)
        self.assertTrue(session.transcript_available())
        self.assertIsNone(session.transcript)

    def test_falls_back_to_started_at_and_reports_archived(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "hermes"
            _build_store(
                home,
                [
                    {
                        "id": "sess-b",
                        "source": "telegram",
                        "started_at": 1_600_000_000.0,
                        "archived": 1,
                    }
                ],
            )
            with mock.patch.dict("os.environ", {"HERMES_HOME": str(home)}):
                sessions = bridge.discover_hermes()
        self.assertEqual(sessions[0].updated, 1_600_000_000.0)
        self.assertTrue(sessions[0].archived)
        self.assertEqual(sessions[0].surface, "hermes-telegram")

    def test_missing_store_is_not_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with mock.patch.dict("os.environ", {"HERMES_HOME": raw}):
                self.assertEqual(bridge.discover_hermes(), [])

    def test_unreadable_store_degrades_to_empty(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "hermes"
            home.mkdir(parents=True)
            (home / "state.db").write_text("not a database", encoding="utf-8")
            with mock.patch.dict("os.environ", {"HERMES_HOME": str(home)}):
                self.assertEqual(bridge.discover_hermes(), [])

    def test_discovery_never_writes_to_the_hermes_store(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "hermes"
            database = _build_store(
                home, [{"id": "sess-c", "started_at": 1_700_000_000.0}]
            )
            before = database.read_bytes()
            with mock.patch.dict("os.environ", {"HERMES_HOME": str(home)}):
                bridge.discover_hermes()
            self.assertEqual(database.read_bytes(), before)


class HermesTraceParsingTests(unittest.TestCase):
    """`hermes sessions export --format trace` emits Claude Code JSONL."""

    def _trace(self) -> str:
        records = [
            {
                "type": "user",
                "isSidechain": False,
                "sessionId": "sess-a",
                "uuid": "u1",
                "parentUuid": None,
                "timestamp": "2026-07-01T00:00:00Z",
                "message": {"role": "user", "content": "Why did auth break?"},
            },
            {
                "type": "assistant",
                "isSidechain": False,
                "sessionId": "sess-a",
                "uuid": "a1",
                "parentUuid": "u1",
                "timestamp": "2026-07-01T00:00:01Z",
                "message": {
                    "role": "assistant",
                    "model": "hermes-4-70b",
                    "content": [
                        {"type": "text", "text": "The token TTL was halved."},
                        {
                            "type": "tool_use",
                            "id": "toolu_1",
                            "name": "read",
                            "input": {"path": "auth.py"},
                        },
                    ],
                },
            },
            {
                "type": "user",
                "isSidechain": False,
                "sessionId": "sess-a",
                "uuid": "u2",
                "parentUuid": "a1",
                "timestamp": "2026-07-01T00:00:02Z",
                "message": {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_1",
                            "content": "TTL = 300",
                        }
                    ],
                },
            },
        ]
        return "\n".join(json.dumps(record) for record in records) + "\n"

    def test_hermes_trace_records_parse_as_claude_transcript(self) -> None:
        messages = bridge.claude_records_to_messages(
            bridge.read_jsonl_text(self._trace())
        )
        self.assertEqual(
            [(message.role, message.text) for message in messages],
            [
                ("user", "Why did auth break?"),
                ("assistant", "The token TTL was halved."),
            ],
        )

    def test_tool_traffic_is_excluded_from_the_conversation(self) -> None:
        messages = bridge.claude_records_to_messages(
            bridge.read_jsonl_text(self._trace())
        )
        joined = " ".join(message.text for message in messages)
        self.assertNotIn("TTL = 300", joined)
        self.assertNotIn("auth.py", joined)

    def test_malformed_lines_are_skipped(self) -> None:
        text = (
            'not json\n{"type":"user","message":{"role":"user","content":"ok"}}\n[]\n'
        )
        messages = bridge.claude_records_to_messages(bridge.read_jsonl_text(text))
        self.assertEqual([message.text for message in messages], ["ok"])


class BoundedSpoolTests(unittest.TestCase):
    """The byte cap must hold while the child is writing, not after it exits."""

    def _run(self, script: str, limit: int, timeout: float = 30.0):
        with tempfile.TemporaryDirectory() as raw:
            destination = Path(raw) / "out.bin"
            code, detail = bridge._spool_bounded(
                [sys.executable, "-c", script], destination, limit, timeout
            )
            return code, detail, destination.stat().st_size

    def test_normal_output_is_spooled_intact(self) -> None:
        code, detail, size = self._run(
            "import sys; sys.stdout.buffer.write(b'hello world')", 1_000_000
        )
        self.assertEqual((code, detail), (0, ""))
        self.assertEqual(size, len(b"hello world"))

    def test_unbounded_writer_is_killed_during_output(self) -> None:
        # Would run forever and fill the volume if the cap were checked only
        # after the child exited.
        script = (
            "import sys; chunk = b'x' * 65536\n"
            "while True:\n"
            "    sys.stdout.buffer.write(chunk); sys.stdout.buffer.flush()\n"
        )
        started = time.monotonic()
        with self.assertRaises(SystemExit) as caught:
            self._run(script, 200_000)
        elapsed = time.monotonic() - started
        self.assertIn("size limit", str(caught.exception))
        # The process is killed on overflow, so this returns promptly rather
        # than running to the 30s deadline.
        self.assertLess(elapsed, 25.0)

    def test_descendant_holding_the_pipe_cannot_hang_the_reader(self) -> None:
        # The child spawns a grandchild that inherits stdout and sleeps.  If
        # teardown killed only the direct child, the inherited write end would
        # keep read1() blocked forever and hang an unattended agent.
        script = (
            "import subprocess, sys\n"
            "subprocess.Popen([sys.executable, '-c', "
            "'import time; time.sleep(120)'], stdout=sys.stdout)\n"
            "sys.stdout.buffer.write(b'first')\n"
            "sys.stdout.buffer.flush()\n"
            "sys.exit(0)\n"
        )
        started = time.monotonic()
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as raw:
            destination = Path(raw) / "out.bin"
            with self.assertRaises(SystemExit) as caught:
                bridge._spool_bounded(
                    [sys.executable, "-c", script], destination, 1_000_000, 5.0
                )
        elapsed = time.monotonic() - started
        self.assertIn("timed out", str(caught.exception))
        # Bounded by the watchdog plus teardown, not by the grandchild's 120s.
        self.assertLess(elapsed, 45.0)

    def test_stalled_child_is_killed_at_the_deadline(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            self._run("import time; time.sleep(60)", 1_000_000, timeout=1.0)
        self.assertIn("timed out", str(caught.exception))

    def test_stderr_is_returned_but_bounded(self) -> None:
        script = (
            "import sys\n"
            "sys.stderr.write('E' * 100000); sys.stderr.flush()\n"
            "sys.exit(3)\n"
        )
        code, detail, _ = self._run(script, 1_000_000)
        self.assertEqual(code, 3)
        self.assertLessEqual(len(detail), bridge.MAX_PEER_ERROR_BYTES)
        self.assertTrue(detail.startswith("E"))

    def test_failing_child_reports_its_exit_code(self) -> None:
        code, _, _ = self._run("import sys; sys.exit(7)", 1_000_000)
        self.assertEqual(code, 7)


class HermesExportTests(unittest.TestCase):
    def _session(self, session_id: str = "sess-a") -> bridge.Session:
        return bridge.Session(
            provider="hermes",
            surface="hermes-cli",
            session_id=session_id,
            resume_id=session_id,
            transcript=None,
            export_mode="cli",
        )

    def test_export_invokes_hermes_without_disabling_redaction(self) -> None:
        captured: dict = {}

        def fake_spool(command, destination, limit, timeout):
            captured["command"] = command
            captured["limit"] = limit
            destination.write_bytes(b"")
            return 0, ""

        with mock.patch.object(bridge.shutil, "which", return_value="/bin/hermes"):
            with mock.patch.object(bridge, "_spool_bounded", fake_spool):
                bridge.extract_hermes(self._session())
        self.assertEqual(
            captured["command"],
            [
                "/bin/hermes",
                "sessions",
                "export",
                "-",
                "--format",
                "trace",
                "--session-id",
                "sess-a",
            ],
        )
        # Hermes redacts secrets in trace exports unless told not to.  Braid
        # must never be the thing that turns that off.
        self.assertNotIn("--no-redact", captured["command"])
        self.assertEqual(captured["limit"], bridge.MAX_SESSION_FILE_BYTES)

    def test_missing_hermes_cli_is_a_clear_failure(self) -> None:
        with mock.patch.object(bridge.shutil, "which", return_value=None):
            with self.assertRaises(SystemExit) as caught:
                bridge.extract_hermes(self._session())
        self.assertIn("hermes CLI was not found", str(caught.exception))

    def test_option_shaped_session_id_is_refused(self) -> None:
        with mock.patch.object(bridge.shutil, "which", return_value="/bin/hermes"):
            with self.assertRaises(SystemExit) as caught:
                bridge.extract_hermes(self._session("--upload"))
        self.assertIn("not a valid identifier", str(caught.exception))

    def test_failed_export_surfaces_bounded_stderr(self) -> None:
        def fake_spool(command, destination, limit, timeout):
            destination.write_bytes(b"")
            return 1, "no such session"

        with mock.patch.object(bridge.shutil, "which", return_value="/bin/hermes"):
            with mock.patch.object(bridge, "_spool_bounded", fake_spool):
                with self.assertRaises(SystemExit) as caught:
                    bridge.extract_hermes(self._session())
        self.assertIn("no such session", str(caught.exception))

    def test_export_parses_spooled_trace_records(self) -> None:
        record = {"type": "user", "message": {"role": "user", "content": "spooled"}}

        def fake_spool(command, destination, limit, timeout):
            destination.write_bytes((json.dumps(record) + "\n").encode("utf-8"))
            return 0, ""

        with mock.patch.object(bridge.shutil, "which", return_value="/bin/hermes"):
            with mock.patch.object(bridge, "_spool_bounded", fake_spool):
                messages = bridge.extract_hermes(self._session())
        self.assertEqual([message.text for message in messages], ["spooled"])


class HermesPeerTurnTests(unittest.TestCase):
    def _session(self) -> bridge.Session:
        return bridge.Session(
            provider="hermes",
            surface="hermes-cli",
            session_id="sess-a",
            resume_id="sess-a",
            transcript=None,
            export_mode="cli",
        )

    def test_live_turn_is_refused_because_oneshot_bypasses_approvals(self) -> None:
        # `hermes -z` auto-bypasses tool approvals, so a resumed session's own
        # persisted text could reach write-capable tools with no gate.  Refuse
        # before even looking for the executable.
        def explode(*args, **kwargs):  # pragma: no cover - must not be reached
            raise AssertionError("run_peer must refuse before spawning Hermes")

        with mock.patch.object(bridge.shutil, "which", explode):
            with mock.patch.object(bridge.subprocess, "run", explode):
                for ephemeral, dry_run in ((False, False), (False, True), (True, True)):
                    with self.subTest(ephemeral=ephemeral, dry_run=dry_run):
                        with self.assertRaises(SystemExit) as caught:
                            bridge.run_peer(
                                self._session(), "status?", ephemeral, dry_run
                            )
                        self.assertIn("live Hermes turns", str(caught.exception))

    def test_refusal_points_at_the_read_only_alternatives(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            bridge.run_peer(self._session(), "status?", False, False)
        message = str(caught.exception)
        self.assertIn("session export", message)
        self.assertIn("handoff", message)


class HermesHandoffLocalityTests(unittest.TestCase):
    """A local database proves location, never authorship."""

    def _handoff(self):
        import context_handoff

        return context_handoff

    def _session(self, source: str) -> bridge.Session:
        return bridge.Session(
            provider="hermes",
            surface=f"hermes-{source}",
            session_id="sess-a",
            resume_id="sess-a",
            transcript=None,
            export_mode="cli",
        )

    def test_gateway_sourced_sessions_are_refused(self) -> None:
        handoff = self._handoff()
        for source in ("telegram", "discord", "slack", "webui", "gateway", "cron"):
            with self.subTest(source=source):
                with self.assertRaises(handoff.HandoffRefused) as caught:
                    handoff.assert_source_is_local(self._session(source))
                self.assertIn("remote gateway", str(caught.exception))

    def test_first_party_sources_reach_the_store_check(self) -> None:
        handoff = self._handoff()
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "hermes"
            _build_store(home, [{"id": "sess-a", "started_at": 1_700_000_000.0}])
            with mock.patch.dict("os.environ", {"HERMES_HOME": str(home)}):
                for source in sorted(bridge.HERMES_LOCAL_SOURCES):
                    with self.subTest(source=source):
                        handoff.assert_source_is_local(self._session(source))

    def test_missing_store_still_refuses_a_first_party_session(self) -> None:
        handoff = self._handoff()
        with tempfile.TemporaryDirectory() as raw:
            with mock.patch.dict("os.environ", {"HERMES_HOME": raw}):
                with self.assertRaises(handoff.HandoffRefused):
                    handoff.assert_source_is_local(self._session("cli"))


class HermesPathResolutionTests(unittest.TestCase):
    def test_relative_home_still_yields_a_usable_uri(self) -> None:
        # Path.as_uri() raises on a relative path; discovery must not go blind.
        with mock.patch.dict("os.environ", {"HERMES_HOME": "relative-hermes"}):
            database = bridge.hermes_state_db()
        self.assertTrue(database.is_absolute())
        database.as_uri()  # must not raise


class ProviderRegistryTests(unittest.TestCase):
    def test_hermes_is_a_registered_provider_everywhere(self) -> None:
        self.assertIn("hermes", bridge.PROVIDERS)
        self.assertIn("hermes", bridge.PROVIDER_CHOICES)
        self.assertIn("hermes", bridge.DISCOVERY)

    def test_every_provider_is_selectable_on_the_session_parser(self) -> None:
        parser = bridge.build_parser()
        for command in ("list", "resolve", "export", "ask", "handoff"):
            with self.subTest(command=command):
                action = next(
                    item
                    for item in parser._subparsers._group_actions[0]
                    .choices[command]
                    ._actions
                    if item.dest == "provider"
                )
                self.assertIn("hermes", action.choices)


if __name__ == "__main__":
    unittest.main()
