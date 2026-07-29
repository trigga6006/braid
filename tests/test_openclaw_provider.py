from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import braid_session as bridge  # noqa: E402


# Transcribed from OpenClaw's own src/state/openclaw-agent-schema.sql, reduced
# to the tables Braid reads.  Kept literal so a drift in the columns Braid
# depends on fails here rather than in the field.
_OPENCLAW_SCHEMA = """
CREATE TABLE schema_meta (
  meta_key TEXT NOT NULL PRIMARY KEY,
  role TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  agent_id TEXT,
  app_version TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;
CREATE TABLE session_nodes (
  session_key TEXT NOT NULL PRIMARY KEY,
  current_session_id TEXT NOT NULL,
  entry_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  status TEXT,
  created_at INTEGER,
  created_via TEXT,
  created_actor_type TEXT,
  created_actor_id TEXT,
  parent_session_key TEXT,
  spawned_by TEXT,
  fork_source_session_key TEXT,
  fork_source_session_id TEXT,
  fork_source_entry_id TEXT,
  label TEXT,
  display_name TEXT,
  category TEXT,
  icon TEXT,
  pinned_at INTEGER,
  archived_at INTEGER,
  last_read_at INTEGER,
  last_interaction_at INTEGER,
  last_activity_at INTEGER
) STRICT;
CREATE TABLE session_windows (
  session_id TEXT NOT NULL PRIMARY KEY,
  session_key TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  model TEXT,
  channel TEXT
) STRICT;
CREATE TABLE transcript_events (
  session_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  event_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (session_id, seq)
) STRICT;
CREATE TABLE session_transcript_active_events (
  session_id TEXT NOT NULL,
  active_position INTEGER NOT NULL,
  event_seq INTEGER NOT NULL,
  message_position INTEGER,
  PRIMARY KEY (session_id, active_position)
) STRICT;
"""


def _message_event(role: str, text: str, index: int) -> str:
    return json.dumps(
        {
            "type": "message",
            "id": f"e-{index}",
            "parentId": f"e-{index - 1}" if index else None,
            "timestamp": f"2026-07-01T00:00:{index:02d}Z",
            "message": {"role": role, "content": [{"type": "text", "text": text}]},
        }
    )


def _build_store(
    state_dir: Path,
    agent_id: str = "main",
    *,
    session_key: str = "agent:main:main",
    session_id: str = "s-1",
    created_via: str | None = "operator",
    events: list[tuple[str, str]] | None = None,
    active: bool = True,
    entry: dict | None = None,
    last_active_ms: int = 1_780_000_000_000,
    archived: bool = False,
) -> Path:
    database = state_dir / "agents" / agent_id / "agent" / "openclaw-agent.sqlite"
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database)
    try:
        connection.executescript(_OPENCLAW_SCHEMA)
        connection.execute(
            "INSERT INTO schema_meta (meta_key, role, schema_version, created_at,"
            " updated_at) VALUES ('agent', 'agent', 42, 0, 0)"
        )
        connection.execute(
            "INSERT INTO session_nodes (session_key, current_session_id, entry_json,"
            " updated_at, created_via, display_name, archived_at, last_interaction_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                session_key,
                session_id,
                json.dumps(entry or {"execCwd": "/work/proj"}),
                last_active_ms,
                created_via,
                "Auth rollout",
                last_active_ms if archived else None,
                last_active_ms,
            ),
        )
        connection.execute(
            "INSERT INTO session_windows (session_id, session_key, created_at,"
            " updated_at, model) VALUES (?, ?, 0, ?, 'claw-1')",
            (session_id, session_key, last_active_ms),
        )
        for index, (role, text) in enumerate(events or []):
            connection.execute(
                "INSERT INTO transcript_events (session_id, seq, event_json,"
                " created_at) VALUES (?, ?, ?, ?)",
                (session_id, index, _message_event(role, text, index), last_active_ms),
            )
            if active:
                connection.execute(
                    "INSERT INTO session_transcript_active_events (session_id,"
                    " active_position, event_seq, message_position)"
                    " VALUES (?, ?, ?, ?)",
                    (session_id, index, index, index),
                )
        connection.commit()
    finally:
        connection.close()
    return database


class OpenClawStateDirTests(unittest.TestCase):
    def test_explicit_state_dir_wins_outright(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {"OPENCLAW_STATE_DIR": "/custom/state", "OPENCLAW_HOME": "/elsewhere"},
        ):
            self.assertEqual(bridge.openclaw_state_dirs(), [Path("/custom/state")])

    def test_prefers_openclaw_then_legacy_clawdbot(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            (home / ".clawdbot").mkdir()
            with mock.patch.dict(
                "os.environ", {"OPENCLAW_HOME": str(home), "OPENCLAW_STATE_DIR": ""}
            ):
                self.assertEqual(bridge.openclaw_state_dirs(), [home / ".clawdbot"])
                (home / ".openclaw").mkdir()
                # Exactly one default root: reading both would resurrect
                # pre-migration sessions and collide with current keys.
                self.assertEqual(bridge.openclaw_state_dirs(), [home / ".openclaw"])

    def test_named_profiles_are_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            (home / ".openclaw").mkdir()
            (home / ".openclaw-work").mkdir()
            # A migration backup must not be mistaken for a live profile.
            (home / ".openclaw.pre-migration").mkdir()
            with mock.patch.dict(
                "os.environ", {"OPENCLAW_HOME": str(home), "OPENCLAW_STATE_DIR": ""}
            ):
                found = bridge.openclaw_state_dirs()
        self.assertIn(home / ".openclaw-work", found)
        self.assertNotIn(home / ".openclaw.pre-migration", found)

    def test_state_dir_is_not_platform_dependent(self) -> None:
        # Unlike Hermes, OpenClaw uses the user profile on Windows too.
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            (home / ".openclaw").mkdir()
            with mock.patch.dict(
                "os.environ",
                {
                    "OPENCLAW_HOME": str(home),
                    "OPENCLAW_STATE_DIR": "",
                    "LOCALAPPDATA": r"C:\Users\x\AppData\Local",
                },
            ):
                with mock.patch.object(bridge.sys, "platform", "win32"):
                    self.assertEqual(bridge.openclaw_state_dirs(), [home / ".openclaw"])


class OpenClawDiscoveryTests(unittest.TestCase):
    def _discover(self, state_dir: Path):
        with mock.patch.dict("os.environ", {"OPENCLAW_STATE_DIR": str(state_dir)}):
            return bridge.discover_openclaw()

    def test_discovers_sessions_with_stable_key_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw) / ".openclaw"
            _build_store(state, events=[("user", "hi")])
            sessions = self._discover(state)
        self.assertEqual(len(sessions), 1)
        session = sessions[0]
        self.assertEqual(session.provider, "openclaw")
        self.assertEqual(session.surface, "openclaw-main")
        # The session key is the durable identity; the generation id rotates.
        self.assertEqual(session.session_id, "agent:main:main")
        self.assertEqual(session.resume_id, "agent:main:main")
        self.assertEqual(session.origin, "operator")
        self.assertEqual(session.cwd, "/work/proj")
        self.assertTrue(session.transcript_available())
        self.assertIsNone(session.transcript)

    def test_millisecond_timestamps_are_normalized_to_seconds(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw) / ".openclaw"
            _build_store(state, last_active_ms=1_780_000_000_000)
            sessions = self._discover(state)
        self.assertEqual(sessions[0].updated, 1_780_000_000.0)
        self.assertTrue(sessions[0].public()["updated"].startswith("2026-"))

    def test_incognito_store_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw) / ".openclaw"
            _build_store(state)
            incognito = (
                state / "agents" / "main" / "agent" / "incognito-openclaw-agent.sqlite"
            )
            incognito.write_bytes(b"")
            stores = []
            with mock.patch.dict("os.environ", {"OPENCLAW_STATE_DIR": str(state)}):
                stores = [str(path) for _agent, path in bridge.openclaw_databases()]
        self.assertTrue(all("incognito" not in path for path in stores))

    def test_missing_and_corrupt_stores_degrade_to_empty(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw) / ".openclaw"
            state.mkdir()
            self.assertEqual(self._discover(state), [])
            database = state / "agents" / "main" / "agent" / "openclaw-agent.sqlite"
            database.parent.mkdir(parents=True)
            database.write_text("not a database", encoding="utf-8")
            self.assertEqual(self._discover(state), [])

    def test_schema_version_is_reported_for_drift_detection(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw) / ".openclaw"
            database = _build_store(state)
            self.assertEqual(bridge.openclaw_schema_version(database), 42)

    def test_discovery_never_writes_to_the_store(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw) / ".openclaw"
            database = _build_store(state, events=[("user", "hi")])
            before = database.read_bytes()
            self._discover(state)
            self.assertEqual(database.read_bytes(), before)


class OpenClawExtractionTests(unittest.TestCase):
    def _extract(self, state_dir: Path):
        with mock.patch.dict("os.environ", {"OPENCLAW_STATE_DIR": str(state_dir)}):
            session = bridge.discover_openclaw()[0]
            return bridge.extract_openclaw(session)

    def test_reads_user_and_assistant_text(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw) / ".openclaw"
            _build_store(
                state,
                events=[
                    ("user", "Why did auth break?"),
                    ("assistant", "The token TTL was halved."),
                ],
            )
            messages = self._extract(state)
        self.assertEqual(
            [(m.role, m.text) for m in messages],
            [
                ("user", "Why did auth break?"),
                ("assistant", "The token TTL was halved."),
            ],
        )

    def test_only_the_live_branch_is_read(self) -> None:
        """Compaction and rewind leave superseded events in the table."""
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw) / ".openclaw"
            database = _build_store(
                state, events=[("user", "kept"), ("assistant", "also kept")]
            )
            connection = sqlite3.connect(database)
            try:
                # An orphaned event: present in the log, absent from the live
                # branch projection.
                connection.execute(
                    "INSERT INTO transcript_events (session_id, seq, event_json,"
                    " created_at) VALUES ('s-1', 99, ?, 0)",
                    (_message_event("assistant", "ABANDONED BRANCH", 99),),
                )
                connection.commit()
            finally:
                connection.close()
            messages = self._extract(state)
        joined = " ".join(m.text for m in messages)
        self.assertNotIn("ABANDONED", joined)
        self.assertIn("kept", joined)

    def test_empty_active_branch_yields_no_messages(self) -> None:
        # A rewind can empty the live branch. Replaying the raw log instead
        # would resurrect content the session has deliberately moved past.
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw) / ".openclaw"
            _build_store(state, events=[("user", "superseded")], active=False)
            self.assertEqual(self._extract(state), [])

    def test_non_message_events_and_tool_results_are_excluded(self) -> None:
        events = [
            json.dumps({"type": "compaction", "summary": "SUMMARY TEXT"}),
            json.dumps(
                {
                    "type": "message",
                    "message": {
                        "role": "toolResult",
                        "content": [{"type": "text", "text": "TOOL OUT"}],
                    },
                }
            ),
            json.dumps(
                {
                    "type": "message",
                    "message": {
                        "role": "user",
                        "content": [{"type": "text", "text": "real"}],
                    },
                }
            ),
            "not json",
        ]
        messages = bridge.openclaw_events_to_messages(events)
        self.assertEqual([m.text for m in messages], ["real"])

    def test_unknown_session_key_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw) / ".openclaw"
            _build_store(state)
            ghost = bridge.Session(
                provider="openclaw",
                surface="openclaw-main",
                session_id="agent:gone:gone",
                resume_id="agent:gone:gone",
                transcript=None,
                export_mode="openclaw",
                store=str(
                    state / "agents" / "main" / "agent" / "openclaw-agent.sqlite"
                ),
            )
            with mock.patch.dict("os.environ", {"OPENCLAW_STATE_DIR": str(state)}):
                with self.assertRaises(SystemExit) as caught:
                    bridge.extract_openclaw(ghost)
        self.assertIn("no longer in its local store", str(caught.exception))


class OpenClawPeerTurnTests(unittest.TestCase):
    def _session(self, key: str = "agent:main:main") -> bridge.Session:
        return bridge.Session(
            provider="openclaw",
            surface="openclaw-main",
            session_id=key,
            resume_id=key,
            transcript=None,
            export_mode="openclaw",
            origin="operator",
        )

    def test_turn_targets_the_session_and_never_delivers_to_channels(self) -> None:
        captured: dict = {}

        def fake_run(command, **kwargs):
            captured["command"] = command
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps({"payloads": [{"text": "done"}], "meta": {}}),
                stderr="",
            )

        with mock.patch.object(bridge.shutil, "which", return_value="/bin/openclaw"):
            with mock.patch.object(bridge.subprocess, "run", fake_run):
                result = bridge.run_peer(self._session(), "status?", False, False)
        self.assertEqual(
            captured["command"][:4],
            ["/bin/openclaw", "agent", "--session-key", "agent:main:main"],
        )
        self.assertIn("--json", captured["command"])
        # Delivery is opt-in; a bridged turn must not broadcast to channels.
        self.assertNotIn("--deliver", captured["command"])
        self.assertEqual(result, "done\n")

    def test_in_flight_status_is_reported_not_retried(self) -> None:
        payload = json.dumps({"meta": {"status": "in_flight"}, "payloads": []})
        with self.assertRaises(SystemExit) as caught:
            bridge.openclaw_reply_text(payload)
        self.assertIn("already has an active run", str(caught.exception))

    def test_ephemeral_is_refused_rather_than_silently_dropped(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            bridge.run_peer(self._session(), "status?", True, True)
        self.assertIn("no ephemeral turn", str(caught.exception))

    def test_option_shaped_session_key_is_refused(self) -> None:
        with mock.patch.object(bridge.shutil, "which", return_value="/bin/openclaw"):
            with self.assertRaises(SystemExit) as caught:
                bridge.run_peer(self._session("--deliver"), "x", False, False)
        self.assertIn("not a valid identifier", str(caught.exception))

    def test_missing_cli_is_a_clear_failure(self) -> None:
        with mock.patch.object(bridge.shutil, "which", return_value=None):
            with self.assertRaises(SystemExit) as caught:
                bridge.run_peer(self._session(), "x", False, False)
        self.assertIn("openclaw CLI was not found", str(caught.exception))


class OpenClawHandoffLocalityTests(unittest.TestCase):
    def _handoff(self):
        import context_handoff

        return context_handoff

    def _bound(self, state: Path, origin: str, key: str = "agent:main:main"):
        """A session bound to the store it was actually discovered in."""
        return bridge.Session(
            provider="openclaw",
            surface="openclaw-main",
            session_id=key,
            resume_id=key,
            transcript=None,
            export_mode="openclaw",
            origin=origin,
            store=str(state / "agents" / "main" / "agent" / "openclaw-agent.sqlite"),
        )

    def test_non_operator_origins_are_refused(self) -> None:
        handoff = self._handoff()
        for origin in ("channel", "cron", "spawn", "plugin", "internal"):
            with self.subTest(origin=origin):
                with tempfile.TemporaryDirectory() as raw:
                    state = Path(raw) / ".openclaw"
                    _build_store(state, created_via=origin)
                    with mock.patch.dict(
                        "os.environ", {"OPENCLAW_STATE_DIR": str(state)}
                    ):
                        with self.assertRaises(handoff.HandoffRefused) as caught:
                            handoff.assert_source_is_local(self._bound(state, origin))
                self.assertIn("not necessarily authored by you", str(caught.exception))

    def test_operator_origin_is_accepted(self) -> None:
        handoff = self._handoff()
        for origin in sorted(bridge.OPENCLAW_LOCAL_ORIGINS):
            with self.subTest(origin=origin):
                with tempfile.TemporaryDirectory() as raw:
                    state = Path(raw) / ".openclaw"
                    _build_store(state, created_via=origin)
                    with mock.patch.dict(
                        "os.environ", {"OPENCLAW_STATE_DIR": str(state)}
                    ):
                        handoff.assert_source_is_local(self._bound(state, origin))

    def test_origin_is_reread_from_the_bound_store_not_trusted_from_discovery(
        self,
    ) -> None:
        """A carried origin must not be able to vouch for a different store.

        Session keys are not unique across OpenClaw profiles and agents. If the
        gate trusted the value attached at discovery, a session record found in
        one database could authorize committing a channel transcript from
        another.
        """
        handoff = self._handoff()
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw) / ".openclaw"
            # The bound store says 'channel'; the Session claims 'operator'.
            _build_store(state, created_via="channel")
            with mock.patch.dict("os.environ", {"OPENCLAW_STATE_DIR": str(state)}):
                with self.assertRaises(handoff.HandoffRefused) as caught:
                    handoff.assert_source_is_local(self._bound(state, "operator"))
        self.assertIn("'channel'", str(caught.exception))

    def test_unbound_session_is_refused(self) -> None:
        handoff = self._handoff()
        session = bridge.Session(
            provider="openclaw",
            surface="openclaw-main",
            session_id="agent:main:main",
            resume_id="agent:main:main",
            transcript=None,
            export_mode="openclaw",
            origin="operator",
        )
        with self.assertRaises(handoff.HandoffRefused):
            handoff.assert_source_is_local(session)


class OpenClawStoreBindingTests(unittest.TestCase):
    def test_extraction_reads_only_the_bound_store(self) -> None:
        """Two profiles, same session key, different content and origin."""
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            default = home / ".openclaw"
            profile = home / ".openclaw-work"
            _build_store(default, created_via="channel", events=[("user", "REMOTE")])
            _build_store(profile, created_via="operator", events=[("user", "MINE")])
            with mock.patch.dict(
                "os.environ", {"OPENCLAW_HOME": str(home), "OPENCLAW_STATE_DIR": ""}
            ):
                sessions = bridge.discover_openclaw()
                self.assertEqual(len(sessions), 2, sessions)
                by_origin = {session.origin: session for session in sessions}
                mine = bridge.extract_openclaw(by_origin["operator"])
                remote = bridge.extract_openclaw(by_origin["channel"])
        self.assertEqual([m.text for m in mine], ["MINE"])
        self.assertEqual([m.text for m in remote], ["REMOTE"])

    def test_snapshot_returns_origin_and_messages_together(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw) / ".openclaw"
            _build_store(state, created_via="operator", events=[("user", "hi")])
            with mock.patch.dict("os.environ", {"OPENCLAW_STATE_DIR": str(state)}):
                session = bridge.discover_openclaw()[0]
                origin, messages = bridge.openclaw_snapshot(session)
        self.assertEqual(origin, "operator")
        self.assertEqual([m.text for m in messages], ["hi"])


class OpenClawHandoffSnapshotTests(unittest.TestCase):
    def test_handoff_commits_the_snapshot_it_authorized(self) -> None:
        """One read, not two.

        Proving locality already reads the transcript. Reading again before
        committing would let a generation rotation slip content past the
        authorization that approved it.
        """
        import context_handoff

        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw) / ".openclaw"
            _build_store(state, created_via="operator", events=[("user", "authorized")])
            with mock.patch.dict("os.environ", {"OPENCLAW_STATE_DIR": str(state)}):
                session = bridge.discover_openclaw()[0]
                calls = []
                real = bridge.openclaw_snapshot

                def counted(target):
                    calls.append(target.session_id)
                    return real(target)

                with mock.patch.object(bridge, "openclaw_snapshot", counted):
                    messages = context_handoff.assert_source_is_local(session)
        self.assertEqual(len(calls), 1, calls)
        # The proof hands back exactly what it read, so the caller need not
        # (and must not) go back to the store.
        self.assertEqual([m.text for m in messages], ["authorized"])


class OpenClawRegistryTests(unittest.TestCase):
    def test_openclaw_is_registered_everywhere(self) -> None:
        self.assertIn("openclaw", bridge.PROVIDERS)
        self.assertIn("openclaw", bridge.PROVIDER_CHOICES)
        self.assertIn("openclaw", bridge.DISCOVERY)

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
                self.assertIn("openclaw", action.choices)


if __name__ == "__main__":
    unittest.main()
