from __future__ import annotations

from pathlib import Path
import sys
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(SCRIPTS))

import session_bridge as bridge  # noqa: E402


class SessionTranscriptTests(unittest.TestCase):
    def test_codex_fixture_extracts_only_user_and_assistant_text(self) -> None:
        messages = bridge.extract_codex(FIXTURES / "codex-session.jsonl")
        self.assertEqual(
            [(message.role, message.text) for message in messages],
            [
                ("user", "Compare the operating agreements."),
                ("assistant", "The voting thresholds differ."),
            ],
        )

    def test_claude_fixture_excludes_sidechains_and_tool_results(self) -> None:
        messages = bridge.extract_claude(FIXTURES / "claude-session.jsonl")
        self.assertEqual(
            [(message.role, message.text) for message in messages],
            [
                ("user", "Summarize the tax discussion."),
                ("assistant", "The discussion favored partnership taxation."),
            ],
        )

    def test_recent_message_limit_marks_omitted_context(self) -> None:
        messages = [bridge.Message("user", "a" * 80), bridge.Message("assistant", "b" * 80)]
        selected, omitted = bridge.limited_messages(messages, 100)
        self.assertEqual(len(selected), 1)
        self.assertEqual(omitted, 1)
        self.assertIn("truncated", selected[0].text)


if __name__ == "__main__":
    unittest.main()
