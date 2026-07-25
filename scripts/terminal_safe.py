"""One sanitizer for untrusted text on its way to a terminal.

Every human-readable renderer in this project prints strings that came from
somewhere else: a transcript another process wrote, a claim a peer endpoint
authored, a key inside an A2A artifact that has not been verified yet.  A
terminal treats some of those bytes as commands rather than text, so printing
them verbatim hands the writer a small amount of control over the reader's
screen:

*   ``ESC`` (and the C1 8-bit ``CSI`` forms) start escape sequences that move
    the cursor, clear the screen, or recolor output.
*   ``LF`` and ``CR`` end or rewind a line, which lets one attacker-controlled
    field forge additional lines that impersonate our own trusted output --
    a statement reading ``"Looks safe\\n  Audit chain verified: yes"`` renders
    as two lines, the second of which the reader has every reason to believe
    came from us.
*   Bidirectional overrides and isolates (U+202A-U+202E, U+2066-U+2069, and
    friends) reorder the glyphs around them, so what is displayed does not
    match what was stored.

``terminal_safe`` renders every one of those visibly, as an escape, and the
result is guaranteed to be a single line.  Backslash itself is deliberately
NOT escaped: Windows paths are a large share of what these renderers print,
and ``C:\\work\\example`` must stay readable.  The ambiguity that leaves (a
literal two-character ``\\n`` looks like an escaped newline) is cosmetic --
what matters is that no real control character survives.

JSON output modes escape control characters correctly on their own; this is
only for the human-readable paths.
"""

from __future__ import annotations

import re


ELLIPSIS = "…"

# Everything a terminal may act on rather than draw.
_UNSAFE = re.compile(
    "["
    "\x00-\x1f"  # C0 controls -- includes TAB, LF, CR and ESC
    "\x7f"  # DEL
    "\u0080-\u009f"  # C1 controls (8-bit CSI, OSC, ...)
    "\u061c"  # ARABIC LETTER MARK
    "\u200e\u200f"  # LEFT-TO-RIGHT / RIGHT-TO-LEFT MARK
    "\u202a-\u202e"  # bidi embeddings and overrides
    "\u2066-\u2069"  # bidi isolates
    "\u2028\u2029"  # LINE / PARAGRAPH SEPARATOR (line breaks in some renderers)
    "]"
)

_NAMED = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _escape(match: re.Match[str]) -> str:
    character = match.group(0)
    named = _NAMED.get(character)
    if named is not None:
        return named
    code = ord(character)
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def terminal_safe(value: object, limit: int | None = None) -> str:
    """Return ``value`` as one printable line with every control escaped.

    ``limit`` caps the rendered length; the default keeps the whole string,
    which is what the untruncated renderers (the incident brief, CLI error
    text) want.
    """
    cleaned = _UNSAFE.sub(_escape, str(value))
    if limit is None or len(cleaned) <= limit:
        return cleaned
    return cleaned[: max(limit - 1, 0)] + ELLIPSIS
