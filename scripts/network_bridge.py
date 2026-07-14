#!/usr/bin/env python3
"""Pair two Session Bridge installations over pinned HTTPS.

This is a proof-of-concept transport for LANs and private overlay networks.  It
keeps all state on the host, uses a one-time pairing secret, and pins the
host's self-signed TLS certificate in the join code.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

import session_bridge as local


CODE_PREFIX = "SB1."
MAX_BODY = 3_000_000
STATE_LOCK = threading.Lock()


def bridge_home() -> Path:
    path = Path(os.environ.get("SESSION_BRIDGE_HOME", Path.home() / ".session-bridge")).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    (path / "rooms").mkdir(exist_ok=True)
    (path / "connections").mkdir(exist_ok=True)
    return path


def room_dir(room_id: str) -> Path:
    safe_id(room_id)
    return bridge_home() / "rooms" / room_id


def connection_path(connection_id: str) -> Path:
    safe_id(connection_id)
    return bridge_home() / "connections" / f"{connection_id}.json"


def safe_id(value: str) -> str:
    if not value or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in value):
        raise SystemExit("Invalid Session Bridge identifier.")
    return value


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def b64encode_json(value: dict[str, Any]) -> str:
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64decode_json(value: str) -> dict[str, Any]:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        decoded = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as error:
        raise SystemExit("The join code is malformed.") from error
    if not isinstance(decoded, dict):
        raise SystemExit("The join code is malformed.")
    return decoded


def encode_code(payload: dict[str, Any]) -> str:
    return CODE_PREFIX + b64encode_json(payload)


def decode_code(code: str) -> dict[str, Any]:
    compact = "".join(code.strip().split())
    if not compact.startswith(CODE_PREFIX):
        raise SystemExit("This is not a Session Bridge SB1 join code.")
    value = b64decode_json(compact[len(CODE_PREFIX):])
    required = {"v", "url", "room", "pair", "fingerprint", "expires"}
    if value.get("v") != 1 or not required.issubset(value):
        raise SystemExit("This join code uses an unsupported format.")
    if int(value["expires"]) < int(time.time()):
        raise SystemExit("This join code has expired. Ask the host to create a new room.")
    return value


def save_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"Unable to read Session Bridge state: {path}") from error
    if not isinstance(value, dict):
        raise SystemExit(f"Invalid Session Bridge state: {path}")
    return value


def state_path(directory: Path) -> Path:
    return directory / "state.json"


def event_path(directory: Path, sequence: int) -> Path:
    return directory / "events" / f"{sequence:08d}.json"


def append_event(directory: Path, state: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    sequence = int(state.get("next_sequence", 1))
    event = {
        "sequence": sequence,
        "created_at": local.iso_time(time.time()),
        **event,
    }
    save_json(event_path(directory, sequence), event)
    state["next_sequence"] = sequence + 1
    save_json(state_path(directory), state)
    return event


def load_events(directory: Path, after: int = 0) -> list[dict[str, Any]]:
    events_dir = directory / "events"
    if not events_dir.exists():
        return []
    events: list[dict[str, Any]] = []
    for path in sorted(events_dir.glob("*.json")):
        try:
            sequence = int(path.stem)
        except ValueError:
            continue
        if sequence > after:
            events.append(load_json(path))
    return events


def make_certificate(directory: Path, hostname: str, expires_at: int) -> str:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError as error:
        raise SystemExit(
            "Network mode needs the Python 'cryptography' package to create a per-room TLS certificate. "
            "Install it with: python -m pip install cryptography"
        ) from error

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Session Bridge proof of concept")])
    names: list[Any] = [x509.DNSName("localhost")]
    try:
        names.append(x509.IPAddress(ipaddress.ip_address(hostname)))
    except ValueError:
        names.append(x509.DNSName(hostname))
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(dt.datetime.fromtimestamp(expires_at, tz=dt.timezone.utc) + dt.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    key_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    (directory / "certificate.pem").write_bytes(cert_bytes)
    (directory / "private-key.pem").write_bytes(key_bytes)
    try:
        (directory / "private-key.pem").chmod(0o600)
    except OSError:
        pass
    return certificate.fingerprint(hashes.SHA256()).hex()


def tailscale_address() -> str:
    executable = shutil.which("tailscale")
    if not executable:
        return ""
    try:
        completed = subprocess.run(
            [executable, "ip", "-4"], capture_output=True, text=True, timeout=3, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout.strip().splitlines()[0] if completed.returncode == 0 and completed.stdout.strip() else ""


def local_address() -> str:
    tailnet = tailscale_address()
    if tailnet:
        return tailnet
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 80))
        return str(sock.getsockname()[0])
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
    finally:
        sock.close()


def choose_port(bind: str, requested: int) -> int:
    if requested:
        return requested
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.bind((bind, 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def advertised_origin(advertise: str, port: int) -> tuple[str, str]:
    if advertise:
        value = advertise.strip().rstrip("/")
        if "://" in value:
            parsed = urlsplit(value)
            if parsed.scheme != "https" or not parsed.hostname:
                raise SystemExit("--advertise URL must be an https:// origin.")
            host = parsed.hostname
            origin = value if parsed.port else f"{value}:{port}"
            return origin, host
        host = value
    else:
        host = local_address()
    rendered = f"[{host}]" if ":" in host else host
    return f"https://{rendered}:{port}", host


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, fingerprint: str, timeout: float = 15):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        super().__init__(host, port, timeout=timeout, context=context)
        self.expected_fingerprint = fingerprint.casefold()

    def connect(self) -> None:
        super().connect()
        certificate = self.sock.getpeercert(binary_form=True) if self.sock else b""
        actual = hashlib.sha256(certificate).hexdigest()
        if not hmac.compare_digest(actual, self.expected_fingerprint):
            self.close()
            raise ssl.SSLError("Session Bridge certificate fingerprint did not match the join code.")


def request_json(
    origin: str,
    fingerprint: str,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    token: str = "",
    timeout: float = 20,
) -> dict[str, Any]:
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not parsed.hostname:
        raise SystemExit("Session Bridge only accepts pinned HTTPS endpoints.")
    port = parsed.port or 443
    connection = PinnedHTTPSConnection(parsed.hostname, port, fingerprint, timeout=timeout)
    payload = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(payload))
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        raw = response.read(MAX_BODY + 1)
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise SystemExit(f"Could not reach the Session Bridge host: {error}") from error
    finally:
        connection.close()
    if len(raw) > MAX_BODY:
        raise SystemExit("The Session Bridge response exceeded the safety limit.")
    try:
        value = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"The host returned an invalid response (HTTP {response.status}).") from error
    if not 200 <= response.status < 300:
        detail = value.get("error", response.reason) if isinstance(value, dict) else response.reason
        raise SystemExit(f"Session Bridge host rejected the request (HTTP {response.status}): {detail}")
    if not isinstance(value, dict):
        raise SystemExit("The host returned an invalid response.")
    return value


class BridgeHandler(BaseHTTPRequestHandler):
    server_version = "SessionBridge/1"

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    @property
    def directory(self) -> Path:
        return self.server.room_directory  # type: ignore[attr-defined]

    def send_value(self, status: int, value: dict[str, Any]) -> None:
        data = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def read_value(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid Content-Length")
        if length <= 0 or length > MAX_BODY:
            raise ValueError("Request body is empty or too large")
        raw = self.rfile.read(length)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def participant(self, state: dict[str, Any]) -> str:
        header = self.headers.get("Authorization", "")
        token = header[7:] if header.startswith("Bearer ") else ""
        candidate = token_hash(token) if token else ""
        for participant_id, participant in state.get("participants", {}).items():
            if hmac.compare_digest(str(participant.get("token_hash", "")), candidate):
                return str(participant_id)
        return ""

    def active_state(self) -> dict[str, Any] | None:
        state = load_json(state_path(self.directory))
        if state.get("closed") or int(state.get("expires", 0)) < int(time.time()):
            self.send_value(410, {"error": "This Session Bridge room is closed or expired."})
            return None
        return state

    def do_GET(self) -> None:
        state = self.active_state()
        if state is None:
            return
        parsed = urlsplit(self.path)
        if parsed.path == "/v1/health":
            self.send_value(200, {"ok": True, "room": state["room_id"]})
            return
        if parsed.path != "/v1/events":
            self.send_value(404, {"error": "Unknown endpoint."})
            return
        participant_id = self.participant(state)
        if not participant_id:
            self.send_value(401, {"error": "Invalid participant token."})
            return
        try:
            after = int(parse_qs(parsed.query).get("after", ["0"])[0])
        except ValueError:
            self.send_value(400, {"error": "Invalid cursor."})
            return
        events = [
            event for event in load_events(self.directory, after)
            if event.get("to") in (participant_id, "all") and event.get("from") == "host"
        ]
        cursor = max([after, *[int(event["sequence"]) for event in events]])
        self.send_value(200, {"events": events, "cursor": cursor})

    def do_POST(self) -> None:
        state = self.active_state()
        if state is None:
            return
        parsed = urlsplit(self.path)
        try:
            value = self.read_value()
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            self.send_value(400, {"error": str(error)})
            return
        if parsed.path == "/v1/join":
            self.handle_join(state, value)
        elif parsed.path == "/v1/message":
            self.handle_message(state, value)
        else:
            self.send_value(404, {"error": "Unknown endpoint."})

    def handle_join(self, state: dict[str, Any], value: dict[str, Any]) -> None:
        supplied = token_hash(str(value.get("pair", "")))
        with STATE_LOCK:
            state = load_json(state_path(self.directory))
            expected = str(state.get("pair_hash", ""))
            if state.get("pair_used") or not hmac.compare_digest(supplied, expected):
                self.send_value(403, {"error": "The pairing code is invalid or has already been used."})
                return
            transcript = value.get("transcript")
            session = value.get("session")
            if not isinstance(transcript, dict) or not isinstance(session, dict):
                self.send_value(400, {"error": "Join request must include a local session transcript."})
                return
            participant_id = "peer-" + secrets.token_hex(4)
            participant_token = secrets.token_urlsafe(32)
            state.setdefault("participants", {})[participant_id] = {
                "token_hash": token_hash(participant_token),
                "session": session,
                "joined_at": local.iso_time(time.time()),
            }
            state["pair_used"] = True
            join_event = append_event(self.directory, state, {
                "type": "join",
                "from": participant_id,
                "to": "host",
                "message": str(value.get("message", "")).strip(),
                "session": session,
                "transcript": transcript,
            })
            state = load_json(state_path(self.directory))
        try:
            host_session = local.resolve_session(str(state["host_session"]))
            host_transcript = local.transcript_payload(host_session, int(state.get("max_chars", 100000)))
        except SystemExit as error:
            self.send_value(500, {"error": f"Host session is no longer available: {error}"})
            return
        self.send_value(200, {
            "room_id": state["room_id"],
            "participant_id": participant_id,
            "participant_token": participant_token,
            "connection_cursor": int(join_event["sequence"]),
            "host_session": host_session.public(),
            "host_transcript": host_transcript,
            "expires": state["expires"],
        })

    def handle_message(self, state: dict[str, Any], value: dict[str, Any]) -> None:
        participant_id = self.participant(state)
        if not participant_id:
            self.send_value(401, {"error": "Invalid participant token."})
            return
        message = str(value.get("message", "")).strip()
        if not message or len(message) > 100000:
            self.send_value(400, {"error": "Message is empty or too large."})
            return
        with STATE_LOCK:
            state = load_json(state_path(self.directory))
            event = append_event(self.directory, state, {
                "type": "message", "from": participant_id, "to": "host", "message": message,
            })
        self.send_value(200, {"accepted": True, "sequence": event["sequence"]})


def read_message(args: argparse.Namespace) -> str:
    sources = sum(bool(value) for value in (getattr(args, "message", None), getattr(args, "message_file", None), getattr(args, "stdin", False)))
    if sources != 1:
        raise SystemExit("Choose exactly one message source: --message, --message-file, or --stdin.")
    if getattr(args, "message_file", None):
        value = Path(args.message_file).expanduser().read_text(encoding="utf-8")
    elif getattr(args, "stdin", False):
        value = sys.stdin.read()
    else:
        value = args.message
    if not value or not value.strip():
        raise SystemExit("The Session Bridge message is empty.")
    return value.strip()


def render_events(events: list[dict[str, Any]], title: str) -> str:
    lines = [f"# {title}", ""]
    if not events:
        lines.extend(["No new messages.", ""])
    for event in events:
        lines.extend([
            f"## Event {event.get('sequence')} — {event.get('type', 'message')}", "",
            f"- From: {event.get('from', '')}",
            f"- To: {event.get('to', '')}",
            f"- Created: {event.get('created_at', '')}", "",
        ])
        if event.get("message"):
            lines.extend([str(event["message"]), ""])
        if isinstance(event.get("transcript"), dict):
            lines.extend([local.render_markdown(event["transcript"]), ""])
    return "\n".join(lines).rstrip() + "\n"


def write_or_print(text: str, output: str | None) -> None:
    if output:
        Path(output).expanduser().write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def command_host(args: argparse.Namespace) -> None:
    session = local.resolve_session(args.session, args.provider)
    if session.transcript is None:
        raise SystemExit("Hosting requires a local transcript for the selected session.")
    bind = args.bind
    port = choose_port(bind, args.port)
    origin, certificate_host = advertised_origin(args.advertise, port)
    room_id = secrets.token_hex(6)
    pairing_secret = secrets.token_urlsafe(24)
    expires = int(time.time()) + args.expires_minutes * 60
    directory = room_dir(room_id)
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "events").mkdir()
    fingerprint = make_certificate(directory, certificate_host, expires)
    state = {
        "version": 1,
        "room_id": room_id,
        "created_at": local.iso_time(time.time()),
        "expires": expires,
        "closed": False,
        "bind": bind,
        "port": port,
        "origin": origin,
        "fingerprint": fingerprint,
        "pair_hash": token_hash(pairing_secret),
        "pair_used": False,
        "host_session": session.resume_id or session.session_id,
        "host_session_public": session.public(),
        "max_chars": args.max_chars,
        "participants": {},
        "next_sequence": 1,
    }
    save_json(state_path(directory), state)
    code = encode_code({
        "v": 1, "url": origin, "room": room_id, "pair": pairing_secret,
        "fingerprint": fingerprint, "expires": expires,
    })
    log_path = directory / "server.log"
    command = [sys.executable, str(Path(__file__).resolve()), "_serve", "--room", room_id]
    with log_path.open("a", encoding="utf-8") as log:
        options: dict[str, Any] = {"stdin": subprocess.DEVNULL, "stdout": log, "stderr": log}
        if os.name == "nt":
            options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        else:
            options["start_new_session"] = True
        process = subprocess.Popen(command, **options)
    state["pid"] = process.pid
    save_json(state_path(directory), state)
    deadline = time.time() + 5
    while time.time() < deadline:
        if process.poll() is not None:
            detail = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
            raise SystemExit(f"Session Bridge host failed to start.\n{detail}")
        try:
            with socket.create_connection(("127.0.0.1" if bind in ("0.0.0.0", "::") else bind, port), timeout=.2):
                break
        except OSError:
            time.sleep(.1)
    else:
        raise SystemExit(f"Session Bridge host did not start. Check {log_path}")
    result = {
        "room_id": room_id,
        "join_code": code,
        "url": origin,
        "expires": local.iso_time(expires),
        "host_session": session.public(),
        "security": "Pinned HTTPS, one-time pairing secret, one participant. Use only on a trusted LAN or private VPN for this proof of concept.",
        "reachability": "The advertised address must be reachable from the friend's computer. No router port forwarding is created.",
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("Session Bridge is hosting.")
        print(f"Room: {room_id}")
        print(f"Expires: {result['expires']}")
        print("Join code (send this privately):")
        print(code)
        print(result["reachability"])


def command_join(args: argparse.Namespace) -> None:
    code = decode_code(args.code)
    session = local.resolve_session(args.session, args.provider)
    transcript = local.transcript_payload(session, args.max_chars)
    message = ""
    if args.message or args.message_file or args.stdin:
        message = read_message(args)
    response = request_json(
        str(code["url"]), str(code["fingerprint"]), "POST", "/v1/join",
        {"room": code["room"], "pair": code["pair"], "session": session.public(), "transcript": transcript, "message": message},
        timeout=args.timeout,
    )
    connection_id = f"{response['room_id']}-{response['participant_id']}"
    connection = {
        "version": 1,
        "connection_id": connection_id,
        "room_id": response["room_id"],
        "participant_id": response["participant_id"],
        "participant_token": response["participant_token"],
        "origin": code["url"],
        "fingerprint": code["fingerprint"],
        "cursor": int(response.get("connection_cursor", 0)),
        "expires": response["expires"],
        "local_session": session.public(),
        "host_session": response["host_session"],
    }
    save_json(connection_path(connection_id), connection)
    peer_text = local.render_markdown(response["host_transcript"])
    write_or_print(peer_text, args.output)
    metadata = {
        "connected": True,
        "connection_id": connection_id,
        "room_id": response["room_id"],
        "participant_id": response["participant_id"],
        "host_session": response["host_session"],
        "peer_transcript_output": str(Path(args.output).expanduser()) if args.output else "stdout",
    }
    stream = sys.stdout if args.output else sys.stderr
    stream.write((json.dumps(metadata, indent=2) if args.json else f"Connected. Connection ID: {connection_id}") + "\n")


def load_connection(identifier: str) -> tuple[Path, dict[str, Any]]:
    path = connection_path(identifier)
    if not path.exists():
        matches = list((bridge_home() / "connections").glob(f"*{identifier}*.json"))
        if len(matches) != 1:
            raise SystemExit("Connection ID was not found or is ambiguous.")
        path = matches[0]
    return path, load_json(path)


def command_send(args: argparse.Namespace) -> None:
    _, connection = load_connection(args.connection)
    message = read_message(args)
    response = request_json(
        connection["origin"], connection["fingerprint"], "POST", "/v1/message",
        {"message": message}, connection["participant_token"], timeout=args.timeout,
    )
    print(json.dumps(response, indent=2) if args.json else f"Message accepted as event {response['sequence']}.")


def command_poll(args: argparse.Namespace) -> None:
    path, connection = load_connection(args.connection)
    deadline = time.time() + max(0, args.wait)
    response: dict[str, Any]
    while True:
        response = request_json(
            connection["origin"], connection["fingerprint"], "GET",
            f"/v1/events?after={int(connection.get('cursor', 0))}", token=connection["participant_token"], timeout=args.timeout,
        )
        if response.get("events") or time.time() >= deadline:
            break
        time.sleep(min(1, max(.1, deadline - time.time())))
    connection["cursor"] = max(int(connection.get("cursor", 0)), int(response.get("cursor", 0)))
    save_json(path, connection)
    text = json.dumps(response, indent=2) + "\n" if args.json else render_events(response.get("events", []), "Session Bridge Replies")
    write_or_print(text, args.output)


def command_inbox(args: argparse.Namespace) -> None:
    directory = room_dir(args.room)
    state = load_json(state_path(directory))
    events = [event for event in load_events(directory, args.after) if event.get("to") == "host"]
    text = json.dumps({"room": state["room_id"], "events": events}, indent=2) + "\n" if args.json else render_events(events, "Session Bridge Inbox")
    write_or_print(text, args.output)


def command_reply(args: argparse.Namespace) -> None:
    directory = room_dir(args.room)
    state = load_json(state_path(directory))
    peer = args.peer
    if peer not in state.get("participants", {}):
        raise SystemExit("That peer is not joined to this room. Run inbox to obtain its peer ID.")
    message = read_message(args)
    with STATE_LOCK:
        state = load_json(state_path(directory))
        event = append_event(directory, state, {"type": "message", "from": "host", "to": peer, "message": message})
    print(json.dumps(event, indent=2) if args.json else f"Reply queued as event {event['sequence']}.")


def command_close(args: argparse.Namespace) -> None:
    directory = room_dir(args.room)
    state = load_json(state_path(directory))
    state["closed"] = True
    state["closed_at"] = local.iso_time(time.time())
    save_json(state_path(directory), state)
    print(f"Closed Session Bridge room {args.room}.")


def command_serve(args: argparse.Namespace) -> None:
    directory = room_dir(args.room)
    state = load_json(state_path(directory))
    server = ThreadingHTTPServer((state["bind"], int(state["port"])), BridgeHandler)
    server.room_directory = directory  # type: ignore[attr-defined]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(directory / "certificate.pem", directory / "private-key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.timeout = 1
    try:
        while True:
            current = load_json(state_path(directory))
            if current.get("closed") or int(current.get("expires", 0)) < int(time.time()):
                break
            server.handle_request()
    finally:
        server.server_close()


def add_message_arguments(parser: argparse.ArgumentParser, required: bool = True) -> None:
    parser.add_argument("--message")
    parser.add_argument("--message-file")
    parser.add_argument("--stdin", action="store_true")
    if not required:
        return


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    host = commands.add_parser("host", help="Host a one-peer bridge room and print a join code")
    host.add_argument("--session", required=True)
    host.add_argument("--provider", choices=("all", "codex", "claude"), default="all")
    host.add_argument("--bind", default="0.0.0.0")
    host.add_argument("--advertise", default="", help="Reachable host, IP, or https:// origin placed in the code")
    host.add_argument("--port", type=int, default=0)
    host.add_argument("--expires-minutes", type=int, default=120)
    host.add_argument("--max-chars", type=int, default=100000)
    host.add_argument("--json", action="store_true")
    host.set_defaults(function=command_host)

    join = commands.add_parser("join", help="Join with a code and exchange local transcript context")
    join.add_argument("--code", required=True)
    join.add_argument("--session", required=True)
    join.add_argument("--provider", choices=("all", "codex", "claude"), default="all")
    join.add_argument("--max-chars", type=int, default=100000)
    join.add_argument("--timeout", type=float, default=20)
    join.add_argument("--output")
    join.add_argument("--json", action="store_true")
    add_message_arguments(join, required=False)
    join.set_defaults(function=command_join)

    send = commands.add_parser("send", help="Send a follow-up message from the joined computer")
    send.add_argument("--connection", required=True)
    send.add_argument("--timeout", type=float, default=20)
    send.add_argument("--json", action="store_true")
    add_message_arguments(send)
    send.set_defaults(function=command_send)

    poll = commands.add_parser("poll", help="Poll the host for replies")
    poll.add_argument("--connection", required=True)
    poll.add_argument("--wait", type=int, default=0, help="Wait up to this many seconds")
    poll.add_argument("--timeout", type=float, default=20)
    poll.add_argument("--output")
    poll.add_argument("--json", action="store_true")
    poll.set_defaults(function=command_poll)

    inbox = commands.add_parser("inbox", help="Read joined context and messages on the host")
    inbox.add_argument("--room", required=True)
    inbox.add_argument("--after", type=int, default=0)
    inbox.add_argument("--output")
    inbox.add_argument("--json", action="store_true")
    inbox.set_defaults(function=command_inbox)

    reply = commands.add_parser("reply", help="Reply from the host to its joined peer")
    reply.add_argument("--room", required=True)
    reply.add_argument("--peer", required=True)
    reply.add_argument("--json", action="store_true")
    add_message_arguments(reply)
    reply.set_defaults(function=command_reply)

    close = commands.add_parser("close", help="Close a hosted room")
    close.add_argument("--room", required=True)
    close.set_defaults(function=command_close)

    serve = commands.add_parser("_serve", help=argparse.SUPPRESS)
    serve.add_argument("--room", required=True)
    serve.set_defaults(function=command_serve)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    args.function(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
