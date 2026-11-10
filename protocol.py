"""Wire protocol shared by the Synapse server and client.

TCP is a byte stream, so message boundaries must be explicit.  Every message is
sent as one *frame*::

    +----------------------+--------------------------------------------+
    | 4 bytes, big-endian  | payload (exactly that many bytes)          |
    | payload length       | = AES-256-GCM( JSON header \\n body bytes )  |
    +----------------------+--------------------------------------------+

The JSON header is a single-line object with a ``"type"`` field; the optional
binary *body* is used only for file transfers.  See ``docs/PROTOCOL.md`` for
the full message catalogue.
"""

from __future__ import annotations

import json
import os
import re
import socket
import struct
import sys
import unicodedata
from typing import Any, Dict, Optional, Tuple

from crypto_utils import Cipher, DecryptionError

DEFAULT_PORT = 1535

# --- Limits -----------------------------------------------------------------
MAX_FILE_SIZE = 25 * 1024 * 1024  # bytes of file content per transfer
MAX_FRAME_SIZE = 32 * 1024 * 1024  # upper bound for any single frame (ciphertext)
AUTH_FRAME_LIMIT = 4096  # frames accepted from a client that is not logged in yet
MAX_TEXT_LENGTH = 4000  # characters per chat message
MAX_USERNAME_LENGTH = 32
MAX_PASSWORD_BYTES = 72  # bcrypt ignores (or rejects) anything beyond 72 bytes
MAX_FILENAME_LENGTH = 100  # characters
MAX_FILENAME_BYTES = 200  # UTF-8 bytes (Linux file systems allow 255 per name; leave room for " (1)")
MAX_HEADER_BYTES = 64 * 1024  # size of a message's JSON header (the body is limited separately)
MAX_INTEGER_DIGITS = 20  # no field legitimately holds a number longer than this

# Keep-alive probes let both sides notice a peer that vanished without closing the
# connection (laptop lid closed, Wi-Fi lost) in roughly a minute instead of the OS default.
KEEPALIVE_IDLE = 30  # seconds of silence before the first probe
KEEPALIVE_INTERVAL = 10  # seconds between probes
KEEPALIVE_PROBES = 3  # unanswered probes before the connection is declared dead

_RECV_CHUNK = 256 * 1024  # never allocate more than this ahead of data that has actually arrived
_SMALL_FRAME = 64 * 1024  # frames up to this size are sent with a single call (one packet)

_HEADER = struct.Struct("!I")
_USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]+")
_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul", "conin$", "conout$",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
    "com\u00b9", "com\u00b2", "com\u00b3", "lpt\u00b9", "lpt\u00b2", "lpt\u00b3",
}
# Characters that are invisible or reorder text, so a name like "photo<RLO>gpj.exe" cannot
# masquerade as something else.  (ZWJ/ZWNJ are deliberately kept: scripts such as Persian
# and Urdu need them.)
_INVISIBLE = frozenset(
    "\u00ad\u061c\u200b\u200e\u200f\u202a\u202b\u202c\u202d\u202e"
    "\u2060\u2066\u2067\u2068\u2069\ufeff"
)

Message = Dict[str, Any]


class ProtocolError(Exception):
    """The peer sent something that violates the protocol."""


class ConnectionClosed(ProtocolError):
    """The peer closed the connection (cleanly or in the middle of a frame)."""


# --- Framing ----------------------------------------------------------------
def recv_exact(sock: socket.socket, count: int) -> bytes:
    """Read exactly ``count`` bytes or raise :class:`ConnectionClosed`.

    Memory grows only as data really arrives, so a peer that announces a huge
    frame and then goes silent cannot make us allocate it.
    """
    buffer = bytearray()
    while len(buffer) < count:
        chunk = sock.recv(min(count - len(buffer), _RECV_CHUNK))
        if not chunk:
            raise ConnectionClosed("Connection closed by peer.")
        buffer += chunk
    return bytes(buffer)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    """Send one length-prefixed frame.  Callers must serialise concurrent senders."""
    header = _HEADER.pack(len(payload))
    if len(payload) <= _SMALL_FRAME:
        sock.sendall(header + payload)
    else:  # avoid copying a multi-megabyte payload just to prepend four bytes
        sock.sendall(header)
        sock.sendall(payload)


def recv_frame(sock: socket.socket, max_size: int = MAX_FRAME_SIZE) -> bytes:
    """Receive one frame, refusing to allocate more than ``max_size`` bytes."""
    (length,) = _HEADER.unpack(recv_exact(sock, _HEADER.size))
    if length > max_size:
        raise ProtocolError(f"Frame of {length} bytes exceeds the {max_size} byte limit.")
    return recv_exact(sock, length)


def enable_keepalive(sock: socket.socket) -> None:
    """Turn on TCP keep-alive with short timers.  Best effort: never raises."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        return
    if hasattr(socket, "SIO_KEEPALIVE_VALS"):  # Windows
        try:
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, KEEPALIVE_IDLE * 1000, KEEPALIVE_INTERVAL * 1000))
        except (OSError, ValueError):
            pass
        return
    darwin = sys.platform == "darwin"
    options = (
        (getattr(socket, "TCP_KEEPIDLE", None) or getattr(socket, "TCP_KEEPALIVE", 0x10 if darwin else None),
         KEEPALIVE_IDLE),
        (getattr(socket, "TCP_KEEPINTVL", 0x101 if darwin else None), KEEPALIVE_INTERVAL),
        (getattr(socket, "TCP_KEEPCNT", 0x102 if darwin else None), KEEPALIVE_PROBES),
    )
    for option, value in options:
        if option is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, option, value)
            except OSError:
                pass


# --- Messages ---------------------------------------------------------------
def encode_message(cipher: Cipher, message: Message, body: bytes = b"") -> bytes:
    """Serialise and encrypt one message (JSON header plus optional binary body)."""
    header = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
    # json.dumps never emits a raw newline (it escapes them), so "\n" is a safe separator.
    return cipher.encrypt(header.encode("utf-8") + b"\n" + body)


def _parse_int(text: str) -> int:
    # Converting a giant integer literal is quadratic on Python < 3.11, so refuse it up front.
    if len(text) > MAX_INTEGER_DIGITS:
        raise ValueError("number too large")
    return int(text)


def decode_message(cipher: Cipher, payload: bytes) -> Tuple[Message, bytes]:
    """Inverse of :func:`encode_message`.  Raises :class:`ProtocolError` on bad input."""
    try:
        plaintext = cipher.decrypt(payload)
    except DecryptionError as exc:
        raise ProtocolError(str(exc)) from exc
    header, separator, body = plaintext.partition(b"\n")
    if not separator:
        raise ProtocolError("Message is missing its header separator.")
    if len(header) > MAX_HEADER_BYTES:
        raise ProtocolError(f"Message header is larger than {MAX_HEADER_BYTES} bytes.")
    try:
        message = json.loads(header.decode("utf-8"), parse_int=_parse_int)
        if isinstance(message, dict):
            # Reject strings that cannot be encoded back to UTF-8 (lone surrogates such as
            # "\ud800"): they would crash whoever relays or displays the message later.
            json.dumps(message, ensure_ascii=False).encode("utf-8")
    except (UnicodeError, ValueError, RecursionError) as exc:  # RecursionError: absurdly nested JSON
        raise ProtocolError("Message header is not valid JSON.") from exc
    if not isinstance(message, dict) or not isinstance(message.get("type"), str):
        raise ProtocolError("Message header must be an object with a string 'type'.")
    return message, body


def send_message(sock: socket.socket, cipher: Cipher, message: Message, body: bytes = b"") -> None:
    send_frame(sock, encode_message(cipher, message, body))


def recv_message(
    sock: socket.socket, cipher: Cipher, max_size: int = MAX_FRAME_SIZE
) -> Tuple[Message, bytes]:
    return decode_message(cipher, recv_frame(sock, max_size))


# --- Validation helpers -----------------------------------------------------
def validate_username(username: Any) -> Optional[str]:
    """Return an error message if ``username`` is not acceptable, else ``None``."""
    if not isinstance(username, str) or not username:
        return "Username is required."
    if len(username) > MAX_USERNAME_LENGTH:
        return f"Username must be at most {MAX_USERNAME_LENGTH} characters."
    if not _USERNAME_RE.fullmatch(username):
        return "Username may only contain letters, digits, '_', '-' and '.'."
    return None


def validate_password(password: Any) -> Optional[str]:
    """Return an error message if ``password`` is not acceptable, else ``None``."""
    if not isinstance(password, str) or not password:
        return "Password is required."
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return f"Password must be at most {MAX_PASSWORD_BYTES} bytes."
    return None


def validate_text(text: Any) -> Optional[str]:
    """Return an error message if ``text`` is not an acceptable chat message, else ``None``."""
    if not isinstance(text, str) or not text.strip():
        return "Message is empty"
    if len(text) > MAX_TEXT_LENGTH:
        return f"Message is too long (max {MAX_TEXT_LENGTH} characters)"
    # Line breaks and other control characters would let a user forge extra "lines" (for
    # example a message that looks like it came from somebody else) in other people's windows.
    if any(unicodedata.category(char) in ("Cc", "Cs", "Zl", "Zp") for char in text):
        return "Message contains control characters (such as line breaks)"
    return None


def _replace_unsafe(char: str) -> str:
    if char in '<>:"|?*' or char in _INVISIBLE or unicodedata.category(char) in ("Cc", "Cs", "Zl", "Zp"):
        return "_"
    return char


def _too_long(name: str) -> bool:
    return len(name) > MAX_FILENAME_LENGTH or len(name.encode("utf-8")) > MAX_FILENAME_BYTES


def _shorten(name: str) -> str:
    """Cut ``name`` to the length limits (characters and UTF-8 bytes), keeping its extension."""
    if not _too_long(name):
        return name
    stem, ext = os.path.splitext(name)
    ext = ext[:MAX_FILENAME_LENGTH // 2]  # an absurdly long "extension" cannot eat the budget
    while len(ext.encode("utf-8")) > MAX_FILENAME_BYTES // 2:
        ext = ext[:-1]
    stem = stem[:MAX_FILENAME_LENGTH - len(ext)]
    while stem and _too_long(stem + ext):
        stem = stem[:-1]
    return stem + ext


def sanitize_filename(name: Any, default: str = "file") -> str:
    """Reduce an untrusted file name to a safe, single path component.

    Strips any directory part (both ``/`` and ``\\`` separators), control characters,
    shell/Windows-hostile characters, a list of invisible and right-to-left-override
    characters, leading/trailing dots and spaces, prefixes Windows reserved device
    names with ``_``, and shortens over-long names (keeping the extension) to at most
    100 characters and 200 UTF-8 bytes.  The result is always a non-empty single path
    component, and sanitising it again changes nothing.
    """
    if not isinstance(name, str):
        return default
    name = os.path.basename(name.replace("\\", "/"))
    name = _shorten("".join(_replace_unsafe(char) for char in name).strip(" .")).strip(" .")
    if not name:
        return default
    # Windows reserves device names (CON, NUL, COM1, ...) regardless of extension.
    if name.split(".")[0].strip().lower() in _WINDOWS_RESERVED:
        name = _shorten("_" + name).strip(" .")
    return name or default
