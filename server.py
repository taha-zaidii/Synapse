"""Synapse chat server.

Accepts many simultaneous clients, authenticates them against a bcrypt-hashed
user database, and relays public messages, private messages and files between
them.  Every frame is encrypted with the shared secret (see ``crypto_utils``).

Run it with::

    python server.py [--host 0.0.0.0] [--port 1535] [--users-file users.json]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import socket
import sys
import tempfile
import threading
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import bcrypt

from crypto_utils import Cipher, MissingSecretError
from protocol import (
    AUTH_FRAME_LIMIT,
    DEFAULT_PORT,
    MAX_FILE_SIZE,
    ConnectionClosed,
    Message,
    ProtocolError,
    enable_keepalive,
    encode_message,
    recv_message,
    sanitize_filename,
    send_frame,
    validate_password,
    validate_text,
    validate_username,
)

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_USERS_FILE = BASE_DIR / "users.json"
AUTH_TIMEOUT = 15.0  # seconds a new connection has in total to complete the login handshake
FLUSH_TIMEOUT = 10.0  # seconds a leaving client gets to receive its already-queued messages
MAX_PRIVATE_RECIPIENTS = 100
MAX_OUTBOX_BYTES = 64 * 1024 * 1024  # queued, unsent data allowed per client before it is dropped

log = logging.getLogger("synapse.server")


class UserStoreError(Exception):
    """The user database could not be read."""


class UserExistsError(Exception):
    """Registration failed because the username is taken."""


class SessionClosed(BrokenPipeError):
    """A message was queued for a session that is already closing or closed."""


class UserStore:
    """Thread-safe ``{username: bcrypt hash}`` database persisted as JSON."""

    def __init__(self, path, rounds: int = 12):
        self._path = Path(path)
        self._rounds = rounds
        self._lock = threading.Lock()
        self._users = self._load()
        # Hashing a dummy password for unknown users keeps login timing uniform.
        self._dummy_hash = bcrypt.hashpw(b"synapse-dummy", bcrypt.gensalt(rounds=rounds))

    def _load(self) -> Dict[str, str]:
        if not self._path.exists():
            return {}
        try:
            # utf-8-sig: tolerate a byte-order mark added by some Windows editors
            data = json.loads(self._path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            raise UserStoreError(f"Cannot read user database {self._path}: {exc}") from exc
        if not isinstance(data, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in data.items()
        ):
            raise UserStoreError(
                f"{self._path} must contain a JSON object mapping usernames to password hashes."
            )
        return data

    def _save_locked(self) -> None:
        """Atomically replace the database file (caller must hold the lock)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=self._path.parent, prefix=self._path.name + ".", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self._users, handle, indent=2)
            os.replace(tmp_name, self._path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def register(self, username: str, password: str) -> None:
        with self._lock:
            if username in self._users:
                raise UserExistsError(username)
        hashed = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt(rounds=self._rounds)
        ).decode("ascii")
        with self._lock:
            if username in self._users:  # someone registered it while we were hashing
                raise UserExistsError(username)
            self._users[username] = hashed
            try:
                self._save_locked()
            except OSError:
                del self._users[username]
                raise

    def verify(self, username: str, password: str) -> bool:
        with self._lock:
            stored = self._users.get(username)
        candidate = password.encode("utf-8")
        if stored is None:
            bcrypt.checkpw(candidate, self._dummy_hash)
            return False
        try:
            return bcrypt.checkpw(candidate, stored.encode("ascii"))
        except ValueError:  # malformed hash in the database
            return False


class ClientSession:
    """One client connection.

    Outgoing frames go through a queue drained by a dedicated writer thread, so
    (a) frames from different threads can never interleave on the socket, and
    (b) a slow or stalled client can never block anyone else: it is simply
    disconnected once too much data is waiting for it.
    """

    def __init__(self, sock: socket.socket, address: Tuple[str, int], cipher: Cipher):
        self.sock = sock
        self.address = address
        self.cipher = cipher
        self.username: Optional[str] = None
        self.ready = False  # logged in and announced to the other users
        self.disconnected = False  # set once the server has processed the disconnect
        self._outbox: "queue.SimpleQueue[Optional[bytes]]" = queue.SimpleQueue()
        self._pending_bytes = 0  # queued but not yet handed to the writer
        self._closing = False
        self._writer_done = False
        self._flush_timer: Optional[threading.Timer] = None
        self._state_lock = threading.Lock()
        threading.Thread(
            target=self._write_loop, name=f"synapse-writer-{address[1]}", daemon=True
        ).start()

    @property
    def label(self) -> str:
        return f"{self.username or '-'}@{self.address[0]}:{self.address[1]}"

    def send(self, message: Message, body: bytes = b"") -> None:
        """Queue a message for delivery.  Raises ``OSError`` if the session is gone."""
        self.send_payload(encode_message(self.cipher, message, body))

    def send_payload(self, payload: bytes) -> None:
        """Queue an already-encoded frame payload (lets a broadcast encrypt only once)."""
        with self._state_lock:
            if self._closing:
                raise SessionClosed("Session is closed.")
            overflow = self._pending_bytes + len(payload) > MAX_OUTBOX_BYTES
            if not overflow:
                self._pending_bytes += len(payload)
        if overflow:
            self.close()
            raise BrokenPipeError("Client is not reading its messages; dropped.")
        self._outbox.put(payload)

    def _write_loop(self) -> None:
        try:
            while True:
                payload = self._outbox.get()
                if payload is None:  # sentinel: everything queued so far has been sent
                    break
                with self._state_lock:
                    self._pending_bytes -= len(payload)
                try:
                    send_frame(self.sock, payload)
                except OSError:
                    break
        finally:
            with self._state_lock:
                self._writer_done = True
                timer = self._flush_timer
            if timer is not None:
                timer.cancel()
            self._close_socket()

    def finish(self) -> None:
        """Deliver everything already queued, then close the connection.

        A peer that stops reading cannot hold the connection open for ever: after
        ``FLUSH_TIMEOUT`` seconds it is closed regardless.
        """
        with self._state_lock:
            if self._closing:
                return
            self._closing = True
            if self._writer_done:  # the connection already failed: nothing is left to flush
                return
            timer = threading.Timer(FLUSH_TIMEOUT, self.close)
            timer.daemon = True
            self._flush_timer = timer
        try:
            timer.start()
        except RuntimeError:  # no thread available for the timer: close now instead of leaking
            self.close()
            return
        with self._state_lock:
            if self._writer_done:  # the writer exited while we were starting the timer
                timer.cancel()
        self._outbox.put(None)

    def close(self) -> None:
        """Close immediately (idempotent); also wakes a thread blocked in recv()."""
        with self._state_lock:
            self._closing = True
        self._close_socket()
        self._outbox.put(None)  # lets an idle writer thread exit

    def _close_socket(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class ChatServer:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = DEFAULT_PORT,
        *,
        cipher: Cipher,
        users_file=DEFAULT_USERS_FILE,
        bcrypt_rounds: int = 12,
    ):
        self.host = host
        self.port = port
        self.cipher = cipher
        self.users = UserStore(users_file, rounds=bcrypt_rounds)
        self._lock = threading.Lock()
        self._sessions: Dict[str, ClientSession] = {}  # username -> session
        self._connections: Set[ClientSession] = set()  # every open connection
        self._listener: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._stopping = threading.Event()

    # -- lifecycle -----------------------------------------------------------
    @property
    def address(self) -> Tuple[str, int]:
        if self._listener is None:
            raise RuntimeError("Server is not running.")
        return self._listener.getsockname()[:2]

    def start(self) -> None:
        """Bind, listen and start accepting clients in a background thread."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name != "nt":  # on Windows SO_REUSEADDR would allow port hijacking
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((self.host, self.port))
            listener.listen()
        except OSError:
            listener.close()
            raise
        listener.settimeout(0.1)  # lets the accept loop notice shutdown requests quickly
        self._listener = listener
        self.port = listener.getsockname()[1]
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="synapse-accept", daemon=True
        )
        self._accept_thread.start()

    def wait(self) -> None:
        """Block until :meth:`shutdown` is called (or Ctrl+C)."""
        try:
            while not self._stopping.wait(0.5):
                pass
        except KeyboardInterrupt:
            pass

    def shutdown(self) -> None:
        """Stop accepting clients and disconnect everyone.  Safe to call twice."""
        self._stopping.set()
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=5)
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        with self._lock:
            connections = list(self._connections)
        for session in connections:
            session.close()

    # -- connection handling -------------------------------------------------
    def _accept_loop(self) -> None:
        listener = self._listener
        assert listener is not None
        while not self._stopping.is_set():
            try:
                sock, address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stopping.is_set() or listener.fileno() == -1:
                    break
                log.exception("accept() failed; retrying")
                self._stopping.wait(0.1)
                continue
            if self._stopping.is_set():
                sock.close()
                break
            # Whatever goes wrong while setting up ONE connection (for example a peer that
            # already reset it, which makes setsockopt fail with EINVAL on macOS) must never
            # end the loop that serves everybody else.
            try:
                self._start_session(sock, address)
            except OSError as exc:
                log.debug("Dropping connection from %s during setup: %s", address, exc)
                sock.close()
            except Exception:
                log.exception("Could not start a session for %s", address)
                sock.close()

    def _start_session(self, sock: socket.socket, address: Tuple[str, int]) -> None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        enable_keepalive(sock)
        session = ClientSession(sock, address, self.cipher)
        with self._lock:
            self._connections.add(session)
        try:
            threading.Thread(
                target=self._handle,
                args=(session,),
                name=f"synapse-client-{address[1]}",
                daemon=True,
            ).start()
        except BaseException:
            self._disconnect(session)
            session.close()
            raise

    def _handle(self, session: ClientSession) -> None:
        log.debug("Connection from %s", session.label)
        # A hard deadline for the whole handshake: a client that drips bytes (or stays
        # silent) is cut off after AUTH_TIMEOUT seconds no matter what.
        deadline = threading.Timer(AUTH_TIMEOUT, session.close)
        deadline.daemon = True
        try:
            deadline.start()
            if self._authenticate(session):
                deadline.cancel()
                self._chat_loop(session)
        except ConnectionClosed:
            log.debug("%s disconnected", session.label)
        except ProtocolError as exc:
            log.warning("Protocol error from %s: %s", session.label, exc)
        except OSError as exc:
            log.debug("Socket error for %s: %s", session.label, exc)
        except Exception:  # never let one client's bug take the server down
            log.exception("Unexpected error while handling %s", session.label)
        finally:
            deadline.cancel()
            self._disconnect(session)

    def _reject(self, session: ClientSession, reason: str) -> None:
        try:
            session.send({"type": "auth_error", "message": reason})
        except OSError:
            pass

    def _authenticate(self, session: ClientSession) -> bool:
        """Run the login/register handshake.  Returns True if the user is now logged in."""
        message, _ = recv_message(session.sock, self.cipher, max_size=AUTH_FRAME_LIMIT)
        action = message.get("type")
        username = message.get("username")
        password = message.get("password")

        if action == "register":
            error = validate_username(username) or validate_password(password)
            if error:
                self._reject(session, error)
                return False
            try:
                self.users.register(username, password)
            except UserExistsError:
                self._reject(session, "Username already exists")
                return False
            except OSError:
                log.exception("Could not save the user database")
                self._reject(session, "The server could not save the new account")
                return False
            log.info("Registered new user %r from %s", username, session.address[0])
            session.send({"type": "auth_ok", "message": "Registration successful"})
            return False  # the client reconnects to log in

        if action != "login":
            self._reject(session, "Expected a login or register request")
            return False

        if (
            validate_username(username) is not None
            or validate_password(password) is not None
            or not self.users.verify(username, password)
        ):
            log.info("Failed login for %.64r from %s", username, session.address[0])
            self._reject(session, "Invalid username or password")
            return False

        with self._lock:
            already_online = username in self._sessions
            if not already_online:
                session.username = username
                self._sessions[username] = session  # reserved; not "ready" until announced
        if already_online:
            self._reject(session, "This user is already logged in")
            return False

        session.send({"type": "auth_ok", "message": "Login successful"})
        with self._lock:
            session.ready = True
            roster = self._roster_locked()
            log.info("%s logged in (%d online)", session.label, len(roster))
            # Queued while holding the lock, so roster updates reach every client in order.
            self._broadcast_locked({"type": "hello", "user": username, "users": roster})
        return True

    def _chat_loop(self, session: ClientSession) -> None:
        while True:
            message, body = recv_message(session.sock, self.cipher)
            kind = message["type"]
            if kind == "public":
                self._on_public(session, message)
            elif kind == "private":
                self._on_private(session, message)
            elif kind == "file":
                self._on_file(session, message, body)
            elif kind == "attendees":
                with self._lock:
                    session.send({"type": "attendees", "users": self._roster_locked()})
            elif kind == "bye":
                return
            else:
                self._send_error(session, "Unknown message type")

    # -- message handlers ----------------------------------------------------
    @staticmethod
    def _send_error(session: ClientSession, text: str) -> None:
        session.send({"type": "error", "message": text})

    def _on_public(self, session: ClientSession, message: Message) -> None:
        text = message.get("text")
        error = validate_text(text)
        if error:
            self._send_error(session, error)
            return
        self._broadcast({"type": "public", "from": session.username, "text": text}, exclude=session)

    def _on_private(self, session: ClientSession, message: Message) -> None:
        text = message.get("text")
        recipients = message.get("to")
        error = validate_text(text)
        if error:
            self._send_error(session, error)
            return
        if (
            not isinstance(recipients, list)
            or not recipients
            or len(recipients) > MAX_PRIVATE_RECIPIENTS
            or not all(validate_username(r) is None for r in recipients)  # only real usernames exist
        ):
            self._send_error(session, "Choose at least one valid recipient")
            return
        recipients = list(dict.fromkeys(recipients))  # de-duplicate, keep order
        with self._lock:
            targets = [
                self._sessions[name]
                for name in recipients
                if name in self._sessions and self._sessions[name].ready
            ]
        online = {target.username for target in targets}
        missing = [name for name in recipients if name not in online]
        if targets:
            outgoing = {"type": "private", "from": session.username, "to": recipients, "text": text}
            self._deliver(targets, encode_message(self.cipher, outgoing))
        if missing:
            self._send_error(session, "Not online: " + ", ".join(missing))

    def _on_file(self, session: ClientSession, message: Message, body: bytes) -> None:
        declared = message.get("size")
        if not isinstance(declared, int) or isinstance(declared, bool) or declared != len(body):
            self._send_error(session, "File size does not match its contents")
            return
        if len(body) > MAX_FILE_SIZE:
            self._send_error(session, f"File is too large (max {MAX_FILE_SIZE // (1024 * 1024)} MiB)")
            return
        name = sanitize_filename(message.get("name"))
        log.info("%s sent file %r (%d bytes)", session.label, name, len(body))
        self._broadcast(
            {"type": "file", "from": session.username, "name": name, "size": len(body)},
            body,
            exclude=session,
        )

    # -- helpers -------------------------------------------------------------
    def _roster_locked(self) -> List[str]:
        return sorted(name for name, s in self._sessions.items() if s.ready)

    def _broadcast_locked(
        self, message: Message, body: bytes = b"", exclude: Optional[ClientSession] = None
    ) -> None:
        """Queue a message for every ready client.  The caller must hold ``self._lock``.

        Queueing never blocks (it only appends to each client's outbox), so doing it
        under the lock is cheap, and it guarantees that two roster updates reach
        every client in the same order the server made them.
        """
        targets = [s for s in self._sessions.values() if s.ready and s is not exclude]
        if targets:
            self._deliver(targets, encode_message(self.cipher, message, body))

    def _broadcast(
        self, message: Message, body: bytes = b"", exclude: Optional[ClientSession] = None
    ) -> None:
        with self._lock:
            targets = [s for s in self._sessions.values() if s.ready and s is not exclude]
        if targets:
            self._deliver(targets, encode_message(self.cipher, message, body))

    @staticmethod
    def _deliver(targets: List[ClientSession], payload: bytes) -> None:
        """Queue one encoded frame for each target; drop any client that cannot take it."""
        for target in targets:
            try:
                target.send_payload(payload)
            except SessionClosed:
                continue  # already leaving: its own disconnect handling takes care of it
            except OSError as exc:
                log.debug("Dropping %s: %s", target.label, exc)
                target.close()  # its own handler thread notices and cleans up

    def _disconnect(self, session: ClientSession) -> None:
        with self._lock:
            if session.disconnected:
                return
            session.disconnected = True
            self._connections.discard(session)
            announce = session.ready
            if session.username and self._sessions.get(session.username) is session:
                del self._sessions[session.username]
            session.ready = False
            if announce:
                roster = self._roster_locked()
                log.info("%s disconnected (%d online)", session.label, len(roster))
                self._broadcast_locked({"type": "left", "user": session.username, "users": roster})
        session.finish()  # flush anything still queued for this client (e.g. an auth error)


def local_ip() -> str:
    """Best-effort LAN address of this machine (no packets are actually sent)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connecting a UDP socket only selects a route; 192.0.2.1 is a reserved documentation address.
        probe.connect(("192.0.2.1", 1))
        return probe.getsockname()[0]
    except OSError:
        pass  # no default route (e.g. an isolated LAN): ask the resolver instead
    finally:
        probe.close()
    try:
        address = socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"
    return address


def _port_number(value: str) -> int:
    port = int(value)
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 0 and 65535")
    return port


_port_number.__name__ = "port"  # argparse shows this in "invalid port value: ..."


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Synapse chat server")
    parser.add_argument("--host", default="0.0.0.0", help="interface to listen on (default: all)")
    parser.add_argument("--port", type=_port_number, default=DEFAULT_PORT,
                        help=f"TCP port (default: {DEFAULT_PORT})")
    parser.add_argument("--users-file", default=str(DEFAULT_USERS_FILE),
                        help="path of the user database (default: users.json next to server.py)")
    parser.add_argument("-v", "--verbose", action="store_true", help="log debug details")
    return parser.parse_args(argv)


def describe_reachability(host: str, port: int) -> str:
    """The line telling the user which address clients should connect to."""
    if host in ("", "0.0.0.0"):
        address = local_ip()
        if address.startswith("127."):  # no usable network address was found
            return f"No network address found: only clients on this machine can connect (use 127.0.0.1:{port})"
        return f"Clients on your network can connect to {address}:{port}"
    if host.startswith("127.") or host == "localhost":
        return f"Only clients on this machine can connect (use 127.0.0.1:{port})"
    return f"Clients can connect to {host}:{port}"


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        cipher = Cipher.from_environment()
    except MissingSecretError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        server = ChatServer(args.host, args.port, cipher=cipher, users_file=args.users_file)
        server.start()
    except UserStoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: cannot listen on {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 1

    # flush=True: when output goes to a file, a pipe or a container log it is block-buffered,
    # and the user would not see the address clients should use until much later.
    print(f"Synapse server listening on {args.host}:{server.port}", flush=True)
    print(describe_reachability(args.host, server.port), flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    try:
        server.wait()
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
