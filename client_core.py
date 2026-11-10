"""Network and file-handling logic of the Synapse client (no GUI code).

The GUI in ``client.pyw`` is a thin layer on top of :class:`ChatConnection`.
Two background threads do the network work and never touch any GUI widget: a
receiver that turns incoming messages into plain ``dict`` events on
:attr:`ChatConnection.events`, and a writer that sends queued messages (so a
large file upload can never freeze the caller).  The GUI drains the event queue
from its own thread.  Keeping the two apart makes the client both thread-safe
and testable without a display.

Events put on the queue (all are plain dicts with a ``"type"`` key):

========================  =====================================================
``public``                ``from``, ``text``
``private``               ``from``, ``to`` (list), ``text``
``hello`` / ``left``      ``user``, ``users`` (current roster)
``attendees``             ``users``
``file``                  ``from``, ``name``, ``path``, ``size`` (already saved)
``file_sent``             ``name``, ``size`` (a ``send_file_in_background`` finished)
``error``                 ``message``
``disconnected``          ``reason`` (the connection was lost)
========================  =====================================================

Text that arrives from the network is cleaned (control characters replaced)
before it is put on the queue, so a message can never contain line breaks that
make it look like several messages.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import re
import socket
import threading
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from crypto_utils import Cipher
from protocol import (
    AUTH_FRAME_LIMIT,
    MAX_FILE_SIZE,
    ConnectionClosed,
    Message,
    ProtocolError,
    enable_keepalive,
    encode_message,
    recv_message,
    sanitize_filename,
    send_frame,
    send_message,
    validate_text,
)

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DOWNLOADS_DIR = BASE_DIR / "downloads"
CONNECT_TIMEOUT = 5.0  # seconds to establish the TCP connection
AUTH_TIMEOUT = 15.0  # seconds to wait for the server's login reply
WRITER_JOIN_TIMEOUT = 1.0  # how long close() lets queued data (like "bye") drain
DEFAULT_FILE_NAME = "file"  # used when a received file's own name cannot be stored

log = logging.getLogger("synapse.client")

# An outgoing item: the encrypted frame plus an optional callback run once it is on the wire.
_Outgoing = Tuple[bytes, Optional[Callable[[], None]]]


class AuthError(Exception):
    """The server rejected a login or registration request."""


def default_log_file(username: str) -> Path:
    """Each user gets their own log file, so several clients can share one checkout.

    The name combines a readable part with a short hash of the exact username, so
    different usernames (even ones that differ only in capitals or a trailing dot, which
    some file systems treat as the same) can never end up sharing a file.
    """
    readable = re.sub(r"[^a-z0-9_-]+", "_", username.lower())[:24].strip("_") or "user"
    digest = hashlib.sha256(username.encode("utf-8", "replace")).hexdigest()[:8]
    return BASE_DIR / f"chat_log_{readable}-{digest}.jsonl"


def single_line(text: str) -> str:
    """Turn line breaks, tabs and other control characters into spaces (for pasted text)."""
    return "".join(" " if unicodedata.category(c) in ("Cc", "Zl", "Zp") else c for c in text)


def clean_display(text: str) -> str:
    """Make text from the network safe to show: no control characters, no lone surrogates."""
    return "".join(
        ("�" if unicodedata.category(c) == "Cs" else " ")
        if unicodedata.category(c) in ("Cc", "Cs", "Zl", "Zp")
        else c
        for c in text
    )


class ChatLogger:
    """Appends every chat message to a local JSON-lines file, encrypted with the shared secret."""

    def __init__(self, path, cipher: Cipher):
        self._path = Path(path)
        self._cipher = cipher
        self._lock = threading.Lock()

    def log(self, sender: str, text: str, kind: str, recipients: Optional[Iterable[str]] = None) -> None:
        entry = {
            "sender": sender,
            "message": self._cipher.encrypt_text(text),
            "message_type": kind,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "recipients": list(recipients or []),
        }
        try:
            with self._lock, open(self._path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
        except OSError as exc:
            log.warning("Could not write to the chat log: %s", exc)

    def read(self) -> List[Dict[str, Any]]:
        """Return all logged entries with their messages decrypted (oldest first)."""
        entries = []
        try:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return entries
        for line in lines:
            if line.strip():
                entry = json.loads(line)
                entry["message"] = self._cipher.decrypt_text(entry["message"])
                entries.append(entry)
        return entries


def save_received_file(directory, name: str, data: bytes) -> Path:
    """Save ``data`` into ``directory`` under a sanitised, never-overwriting name.

    The name comes from the network, so it is reduced to a single safe path
    component; an existing file is never replaced (``name (1).ext`` is used).
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    safe_name = sanitize_filename(name)
    stem, ext = os.path.splitext(safe_name)
    counter = 0
    while True:
        candidate = directory / (safe_name if counter == 0 else f"{stem} ({counter}){ext}")
        try:
            handle = open(candidate, "xb")  # "x": fail rather than overwrite
        except FileExistsError:
            counter += 1
            continue
        except OSError:
            if safe_name == DEFAULT_FILE_NAME:
                raise
            # The file system refused this (valid-looking) name, so keep the file under a plain one.
            safe_name = DEFAULT_FILE_NAME
            stem, ext = os.path.splitext(safe_name)
            counter = 0
            continue
        try:
            with handle:
                handle.write(data)
        except BaseException:  # e.g. disk full: do not leave a truncated file behind
            try:
                os.unlink(candidate)
            except OSError:
                pass
            raise
        return candidate


def _clean_users(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [clean_display(user) for user in value if isinstance(user, str)]


class ChatConnection:
    """One connection to a Synapse server: authenticate, then chat."""

    def __init__(
        self,
        host: str,
        port: int,
        cipher: Cipher,
        *,
        downloads_dir=DEFAULT_DOWNLOADS_DIR,
        log_file=None,
    ):
        self.host = host
        self.port = port
        self.cipher = cipher
        self.username: Optional[str] = None
        self.events: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._downloads_dir = Path(downloads_dir)
        self._logger = ChatLogger(log_file, cipher) if log_file else None
        self._sock: Optional[socket.socket] = None
        self._outbox: "queue.SimpleQueue[Optional[_Outgoing]]" = queue.SimpleQueue()
        self._writer: Optional[threading.Thread] = None
        self._state_lock = threading.Lock()
        self._closing = threading.Event()

    # -- connecting ----------------------------------------------------------
    def connect(self) -> None:
        """Open the TCP connection.  Raises ``OSError`` if the server is unreachable."""
        try:
            sock = socket.create_connection((self.host, self.port), timeout=CONNECT_TIMEOUT)
        except (UnicodeError, OverflowError) as exc:  # e.g. a host like "a..b" or a huge port
            raise ConnectionError(f"Invalid server address: {self.host}:{self.port}") from exc
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # only an optimisation
        except OSError:  # e.g. macOS reports EINVAL if the server already reset the connection
            pass
        enable_keepalive(sock)
        self._sock = sock

    def authenticate(self, action: str, username: str, password: str) -> str:
        """Log in (``action="login"``) or create an account (``action="register"``).

        Returns the server's success message.  Raises :class:`AuthError` if the
        server refuses, and ``OSError``/``ProtocolError`` on network or protocol
        problems.  The connection is closed on any failure and after a
        registration (log in afterwards with a fresh connection).
        """
        sock = self._require_socket()
        try:
            sock.settimeout(AUTH_TIMEOUT)
            send_message(
                sock, self.cipher, {"type": action, "username": username, "password": password}
            )
            reply, _ = recv_message(sock, self.cipher, max_size=AUTH_FRAME_LIMIT)
            text = reply.get("message")
            text = clean_display(text) if isinstance(text, str) else ""
            if reply.get("type") != "auth_ok":
                raise AuthError(text or "Authentication failed")
            if action == "login":
                self.username = username
                sock.settimeout(None)
                return text or "Login successful"
            self.close()  # registration done; the server hangs up as well
            return text or "Registration successful"
        except BaseException:
            self.close()
            raise

    def start_listening(self) -> None:
        """Start the background threads that deliver incoming messages as events."""
        self._ensure_writer()
        threading.Thread(target=self._receive_loop, name="synapse-receiver", daemon=True).start()

    # -- receiving -----------------------------------------------------------
    def _receive_loop(self) -> None:
        sock = self._require_socket()
        reason = "Disconnected from the server."
        try:
            while True:
                message, body = recv_message(sock, self.cipher)
                self._dispatch(message, body)
        except ConnectionClosed:
            reason = "The server closed the connection."
        except ProtocolError as exc:
            reason = f"Protocol error: {exc}"
        except OSError as exc:
            reason = f"Connection lost: {exc}"
        finally:
            if not self._closing.is_set():
                self.events.put({"type": "disconnected", "reason": reason})
            self.close()

    def _dispatch(self, message: Message, body: bytes) -> None:
        """Validate one server message and turn it into an event."""
        kind = message["type"]
        sender = message.get("from")
        text = message.get("text")
        if kind == "public" and isinstance(sender, str) and isinstance(text, str):
            sender, text = clean_display(sender), clean_display(text)
            self._record(sender, text, "public")
            self.events.put({"type": "public", "from": sender, "text": text})
        elif kind == "private" and isinstance(sender, str) and isinstance(text, str):
            sender, text = clean_display(sender), clean_display(text)
            recipients = _clean_users(message.get("to"))
            self._record(sender, text, "private", recipients)
            self.events.put({"type": "private", "from": sender, "to": recipients, "text": text})
        elif kind in ("hello", "left") and isinstance(message.get("user"), str):
            self.events.put(
                {
                    "type": kind,
                    "user": clean_display(message["user"]),
                    "users": _clean_users(message.get("users")),
                }
            )
        elif kind == "attendees":
            self.events.put({"type": "attendees", "users": _clean_users(message.get("users"))})
        elif kind == "file" and isinstance(sender, str):
            self._receive_file(clean_display(sender), message, body)
        elif kind == "error" and isinstance(message.get("message"), str):
            self.events.put({"type": "error", "message": clean_display(message["message"])})
        else:
            log.debug("Ignoring unrecognised message of type %r", kind)

    def _receive_file(self, sender: str, message: Message, body: bytes) -> None:
        if message.get("size") != len(body):
            self.events.put({"type": "error", "message": f"Corrupt file received from {sender}."})
            return
        try:
            path = save_received_file(self._downloads_dir, str(message.get("name", "")), body)
        except (OSError, UnicodeError) as exc:
            self.events.put({"type": "error", "message": f"Could not save file from {sender}: {exc}"})
            return
        self._record(sender, f"Received file: {path.name}", "file")
        self.events.put(
            {"type": "file", "from": sender, "name": path.name, "path": str(path), "size": len(body)}
        )

    def _record(self, sender: str, text: str, kind: str, recipients: Optional[Iterable[str]] = None) -> None:
        if self._logger is not None:
            self._logger.log(sender, text, kind, recipients)

    # -- sending -------------------------------------------------------------
    def _ensure_writer(self) -> None:
        with self._state_lock:
            if self._writer is None:
                self._writer = threading.Thread(
                    target=self._write_loop, name="synapse-writer", daemon=True
                )
                self._writer.start()

    def _write_loop(self) -> None:
        sock = self._require_socket()
        while True:
            item = self._outbox.get()
            if item is None:  # sentinel from close(): everything queued before it is sent
                break
            payload, on_sent = item
            try:
                send_frame(sock, payload)
            except OSError as exc:
                if not self._closing.is_set():
                    self.events.put({"type": "error", "message": f"Could not send: {exc}"})
                    # Make the blocked receiver notice and report the lost connection:
                    # shutdown() wakes a blocked recv() on Linux/macOS, close() on Windows.
                    for end_connection in (lambda: sock.shutdown(socket.SHUT_RDWR), sock.close):
                        try:
                            end_connection()
                        except OSError:
                            pass
                break
            if on_sent is not None:
                try:
                    on_sent()
                except Exception:  # a faulty callback must not stop the writer
                    log.exception("on_sent callback failed")

    def _send(self, message: Message, body: bytes = b"", on_sent: Optional[Callable[[], None]] = None) -> None:
        """Queue a message.  Never blocks, even while a big file is being uploaded."""
        self._require_socket()
        if self._closing.is_set():
            raise ConnectionError("Disconnected from the server.")
        payload = encode_message(self.cipher, message, body)
        self._ensure_writer()
        self._outbox.put((payload, on_sent))

    def send_public(self, text: str) -> None:
        text = single_line(text)
        error = validate_text(text)
        if error:
            raise ValueError(error)
        self._send({"type": "public", "text": text})
        self._record(self.username or "", text, "public")

    def send_private(self, recipients: List[str], text: str) -> None:
        text = single_line(text)
        error = validate_text(text)
        if error:
            raise ValueError(error)
        if not recipients:
            raise ValueError("Choose at least one recipient")
        self._send({"type": "private", "to": list(recipients), "text": text})
        self._record(self.username or "", text, "private", recipients)

    def request_attendees(self) -> None:
        self._send({"type": "attendees"})

    def send_file(self, path, on_sent: Optional[Callable[[int], None]] = None) -> int:
        """Queue a file for sending to everyone.  Returns its size in bytes.

        ``on_sent(size)`` (if given) is called from the writer thread once the
        whole file has actually been written to the connection.
        """
        path = Path(path)
        size = path.stat().st_size
        if size > MAX_FILE_SIZE:
            raise ValueError(f"File is too large (max {MAX_FILE_SIZE // (1024 * 1024)} MiB)")
        data = path.read_bytes()
        callback = (lambda: on_sent(len(data))) if on_sent is not None else None
        self._send({"type": "file", "name": path.name, "size": len(data)}, data, callback)
        self._record(self.username or "", f"Sent file: {path.name}", "file")
        return len(data)

    def send_file_in_background(self, path) -> None:
        """Like :meth:`send_file`, but reads the file off-thread.

        Reports through a ``file_sent`` event when the upload has finished, or an
        ``error`` event if it could not be sent.
        """
        name = Path(path).name

        def work() -> None:
            try:
                size = self.send_file(
                    path,
                    on_sent=lambda sent: self.events.put(
                        {"type": "file_sent", "name": name, "size": sent}
                    ),
                )
            except (OSError, ValueError, ProtocolError) as exc:
                self.events.put({"type": "error", "message": f"Could not send {name}: {exc}"})
            else:
                log.debug("Queued %s (%d bytes)", name, size)

        threading.Thread(target=work, name="synapse-file-reader", daemon=True).start()

    # -- shutdown ------------------------------------------------------------
    def close(self) -> None:
        """Leave politely and close the connection (safe to call more than once)."""
        with self._state_lock:
            if self._closing.is_set():
                return
            self._closing.set()
        sock = self._sock
        if sock is None:
            return
        if self.username is not None:
            # Queue a goodbye behind anything already being sent, and give it a moment.
            self._ensure_writer()
            try:
                self._outbox.put((encode_message(self.cipher, {"type": "bye"}), None))
            except Exception:  # pragma: no cover - encoding a constant message cannot fail
                pass
        self._outbox.put(None)
        writer = self._writer
        if writer is not None and writer is not threading.current_thread():
            writer.join(timeout=WRITER_JOIN_TIMEOUT)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def _require_socket(self) -> socket.socket:
        if self._sock is None:
            raise ConnectionError("Not connected.")
        return self._sock
