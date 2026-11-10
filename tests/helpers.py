"""Shared fixtures for the Synapse test-suite."""

from __future__ import annotations

import queue
import shutil
import tempfile
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from client_core import AuthError, ChatConnection
from crypto_utils import Cipher
from server import ChatServer
from tests.watchdog import WatchdogTestCase

TEST_SECRET = "unit-test-shared-secret"
PASSWORD = "correct horse"

Event = Dict[str, object]


def collect_until(conn: ChatConnection, predicate: Callable[[Event], bool], timeout: float = 10.0) -> List[Event]:
    """Consume events from ``conn`` until one matches; return everything consumed (in order)."""
    deadline = time.monotonic() + timeout
    seen: List[Event] = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"Timed out waiting for an event; consumed so far: {seen!r}")
        try:
            event = conn.events.get(timeout=min(remaining, 0.5))
        except queue.Empty:
            continue
        seen.append(event)
        if predicate(event):
            return seen


def wait_for(conn: ChatConnection, predicate: Callable[[Event], bool], timeout: float = 10.0) -> Event:
    """Return the first event matching ``predicate`` (earlier events are discarded)."""
    return collect_until(conn, predicate, timeout)[-1]


def of_type(kind: str, **fields) -> Callable[[Event], bool]:
    """Predicate: event has this type and (optionally) these field values."""
    return lambda event: event["type"] == kind and all(event.get(k) == v for k, v in fields.items())


class ServerTestCase(WatchdogTestCase):
    """Starts a real server on an ephemeral localhost port for every test."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="synapse-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cipher = Cipher(TEST_SECRET)
        self.users_file = self.tmp / "users.json"
        self.server = ChatServer(
            "127.0.0.1", 0, cipher=self.cipher, users_file=self.users_file, bcrypt_rounds=4
        )
        self.server.start()
        self.addCleanup(self.server.shutdown)
        self._connections: List[ChatConnection] = []
        self.addCleanup(self._close_connections)

    def _close_connections(self) -> None:
        for conn in self._connections:
            conn.close()

    def downloads_dir(self, name: str) -> Path:
        return self.tmp / "downloads" / name

    def new_connection(self, name: str = "anon", cipher: Optional[Cipher] = None) -> ChatConnection:
        conn = ChatConnection(
            "127.0.0.1",
            self.server.port,
            cipher or self.cipher,
            downloads_dir=self.downloads_dir(name),
            log_file=None,
        )
        conn.connect()
        self._connections.append(conn)
        return conn

    def register(self, name: str, password: str = PASSWORD) -> str:
        return self.new_connection(name).authenticate("register", name, password)

    def join(self, name: str, password: str = PASSWORD) -> ChatConnection:
        """Register (if needed), log in, and wait until the server has announced us."""
        try:
            self.register(name, password)
        except AuthError:
            pass  # already registered
        conn = self.new_connection(name)
        conn.authenticate("login", name, password)
        conn.start_listening()
        wait_for(conn, of_type("hello", user=name))
        return conn
