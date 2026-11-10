"""Tests for the GUI-independent client logic (no server needed unless stated)."""

import json
import os
import queue
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import client_core
from client_core import (
    BASE_DIR,
    AuthError,
    ChatConnection,
    ChatLogger,
    clean_display,
    default_log_file,
    save_received_file,
    single_line,
)
from crypto_utils import Cipher
from protocol import ConnectionClosed, ProtocolError, recv_message, send_message

from tests.helpers import PASSWORD, ServerTestCase, collect_until, of_type, wait_for
from tests.watchdog import WatchdogTestCase

CIPHER = Cipher("client-core-test-secret")


class SaveReceivedFileTests(WatchdogTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.downloads = self.root / "downloads"

    def test_saves_into_a_new_directory(self):
        path = save_received_file(self.downloads, "hello.txt", b"hi")
        self.assertEqual(path, self.downloads / "hello.txt")
        self.assertEqual(path.read_bytes(), b"hi")

    def test_traversal_names_stay_inside_the_directory(self):
        for name in ("../../escape.txt", "..\\..\\escape.txt", "/tmp/escape.txt", "a/../../escape.txt"):
            path = save_received_file(self.downloads, name, b"x")
            self.assertEqual(path.parent, self.downloads, name)
        self.assertEqual({p.name for p in self.root.iterdir()}, {"downloads"})

    def test_never_overwrites_existing_files(self):
        names = [save_received_file(self.downloads, "a.tar.gz", bytes([i])).name for i in range(4)]
        self.assertEqual(names, ["a.tar.gz", "a.tar (1).gz", "a.tar (2).gz", "a.tar (3).gz"])
        self.assertEqual((self.downloads / "a.tar.gz").read_bytes(), b"\x00")

    def test_empty_or_hostile_name_gets_a_default(self):
        self.assertEqual(save_received_file(self.downloads, "", b"x").name, "file")
        self.assertEqual(save_received_file(self.downloads, "..", b"x").name, "file (1)")

    def test_does_not_write_through_a_symlink(self):
        self.downloads.mkdir()
        target = self.root / "victim.txt"
        target.write_text("original")
        link = self.downloads / "link.txt"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not available")
        path = save_received_file(self.downloads, "link.txt", b"attack")
        self.assertEqual(target.read_text(), "original")
        self.assertEqual(path.name, "link (1).txt")


class ChatLoggerTests(WatchdogTestCase):
    def test_blank_lines_in_the_log_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "log.jsonl"
            logger = ChatLogger(path, CIPHER)
            logger.log("a", "one", "public")
            with open(path, "a", encoding="utf-8") as handle:
                handle.write("\n   \n")
            logger.log("b", "two", "public")
            self.assertEqual([e["message"] for e in logger.read()], ["one", "two"])

    def test_entries_are_encrypted_and_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "chat_log.jsonl"
            logger = ChatLogger(path, CIPHER)
            logger.log("alice", "meet me at the usual place ☕", "public")
            logger.log("bob", "private note", "private", ["alice", "carol"])
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("usual place", raw)
            self.assertNotIn("private note", raw)
            lines = [json.loads(line) for line in raw.splitlines()]
            self.assertEqual([entry["sender"] for entry in lines], ["alice", "bob"])
            entries = logger.read()
            self.assertEqual(entries[0]["message"], "meet me at the usual place ☕")
            self.assertEqual(entries[1]["recipients"], ["alice", "carol"])
            self.assertEqual(entries[1]["message_type"], "private")
            self.assertRegex(entries[0]["timestamp"], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")

    def test_missing_log_reads_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(ChatLogger(Path(tmp) / "nope.jsonl", CIPHER).read(), [])

    def test_unwritable_log_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            logger = ChatLogger(Path(tmp) / "missing-dir" / "log.jsonl", CIPHER)
            with self.assertLogs("synapse.client", level="WARNING"):
                logger.log("alice", "hi", "public")

    def test_concurrent_logging_keeps_every_line_intact(self):
        with tempfile.TemporaryDirectory() as tmp:
            logger = ChatLogger(Path(tmp) / "log.jsonl", CIPHER)

            def work(n):
                for i in range(50):
                    logger.log(f"user{n}", f"message {n}-{i}", "public")

            threads = [threading.Thread(target=work, args=(n,)) for n in range(6)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(len(logger.read()), 300)


class TextHelperTests(WatchdogTestCase):
    def test_single_line_flattens_line_breaks_and_tabs(self):
        self.assertEqual(single_line("a\nb\r\nc\td\u2028e\u2029f"), "a b  c d e f")
        self.assertEqual(single_line("plain text ünï 🚀"), "plain text ünï 🚀")

    def test_clean_display_removes_everything_that_could_forge_a_line(self):
        cleaned = clean_display("hi\n[12:00] bob: fake\r\x00\x1b[2J\u2028\ud800 end")
        self.assertNotIn("\n", cleaned)
        self.assertNotIn("\r", cleaned)
        self.assertNotIn("\x00", cleaned)
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\u2028", cleaned)
        self.assertNotIn("\ud800", cleaned)
        self.assertTrue(cleaned.startswith("hi ") and cleaned.endswith(" end"))
        self.assertEqual(clean_display("emoji 🚀 عربي ünï"), "emoji 🚀 عربي ünï")

    def test_each_user_gets_their_own_log_file(self):
        alice = default_log_file("alice")
        self.assertEqual(alice.parent, BASE_DIR)
        self.assertRegex(alice.name, r"^chat_log_alice-[0-9a-f]{8}\.jsonl$")
        self.assertEqual(alice, default_log_file("alice"))  # stable between runs
        self.assertNotEqual(alice, default_log_file("bob"))

    def test_usernames_that_look_alike_never_share_a_log_file(self):
        # Capitals, a trailing dot and punctuation are all distinct usernames; case-insensitive
        # file systems and "strip trailing dots" rules must not merge their logs.
        names = ["a", "a.", "A", "a_", "a-", "a.b", "a_b", "Alice", "alice", "ALICE", "x" * 32, "x" * 31]
        files = {default_log_file(name) for name in names}
        self.assertEqual(len(files), len(names))
        self.assertEqual(len({f.name.lower() for f in files}), len(names))  # even ignoring case

    def test_hostile_usernames_cannot_escape_the_folder(self):
        for name in ("../../etc/passwd", "..\\..\\x", "", "\x00", "con", "a/b", "é" * 40, "\ud800"):
            path = default_log_file(name)
            self.assertEqual(path.parent, BASE_DIR, repr(name))
            self.assertRegex(path.name, r"^chat_log_[a-z0-9_-]+-[0-9a-f]{8}\.jsonl$", repr(name))


class ConnectionBasicsTests(WatchdogTestCase):
    def test_unusable_addresses_raise_a_clean_connection_error(self):
        # Host names that cannot be encoded make the resolver raise UnicodeError, which would
        # otherwise escape as a confusing non-OSError.  None of this may depend on what is
        # (or is not) listening on a real port.
        for host in ("a..b", "x" * 300, "."):
            conn = ChatConnection(host, 1535, CIPHER, log_file=None)
            with self.assertRaisesRegex(ConnectionError, "Invalid server address", msg=repr(host[:10])):
                conn.connect()

    def test_unusable_ports_raise_an_oserror(self):
        # Which exact error the resolver raises for a bad port differs between operating systems.
        for port in (99999, -1, 10 ** 10):
            with self.assertRaises(OSError, msg=str(port)):
                ChatConnection("localhost", port, CIPHER, log_file=None).connect()

    def test_connecting_to_nothing_raises_oserror(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with self.assertRaises(OSError):
            ChatConnection("127.0.0.1", port, CIPHER, log_file=None).connect()

    def test_connecting_to_a_closed_port_raises_oserror(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        conn = ChatConnection("127.0.0.1", port, CIPHER, log_file=None)
        with self.assertRaises(OSError):
            conn.connect()

    def test_methods_before_connecting_fail_cleanly(self):
        conn = ChatConnection("127.0.0.1", 1, CIPHER, log_file=None)
        with self.assertRaises(ConnectionError):
            conn.request_attendees()
        conn.close()  # closing a never-connected connection is a no-op
        conn.close()

    def test_local_validation_happens_before_anything_is_sent(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        conn = ChatConnection("x", 1, CIPHER, log_file=None)
        conn._sock = a
        for bad in ("", "   ", "x" * 4001):
            with self.assertRaises(ValueError):
                conn.send_public(bad)
            with self.assertRaises(ValueError):
                conn.send_private(["bob"], bad)
        with self.assertRaises(ValueError):
            conn.send_private([], "hello")
        b.settimeout(0.2)
        with self.assertRaises(socket.timeout):
            b.recv(1)  # nothing reached the wire


class SaveFallbackTests(WatchdogTestCase):
    def test_a_name_the_file_system_rejects_falls_back_to_a_plain_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_open = open

            def picky_open(path, *args, **kwargs):
                if Path(path).name.startswith("refused"):
                    raise OSError(36, "File name too long")
                return real_open(path, *args, **kwargs)

            with mock.patch("client_core.open", picky_open, create=True):
                saved = save_received_file(Path(tmp), "refused-name.txt", b"data")
            self.assertEqual(saved.name, "file")
            self.assertEqual(saved.read_bytes(), b"data")

    def test_a_directory_that_cannot_be_written_still_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("client_core.open", side_effect=PermissionError("denied"), create=True):
                with self.assertRaises(OSError):
                    save_received_file(Path(tmp), "x.txt", b"data")


class WriterTests(WatchdogTestCase):
    """Sends are queued and written by a background thread, so the caller never blocks."""

    def setUp(self):
        self.server_end, client_end = socket.socketpair()
        self.addCleanup(self.server_end.close)
        self.conn = ChatConnection("x", 1, CIPHER, log_file=None)
        self.conn._sock = client_end
        self.conn.username = "me"
        self.addCleanup(self.conn.close)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def test_sending_never_blocks_behind_a_stalled_upload(self):
        big = self.tmp / "big.bin"
        big.write_bytes(os.urandom(3 * 1024 * 1024))
        started = time.monotonic()
        self.conn.send_file(big)  # the peer is not reading: the socket buffer fills up
        self.conn.send_public("typed while the file is still uploading")
        self.conn.request_attendees()
        self.assertLess(time.monotonic() - started, 2.0, "send_* blocked behind the upload")
        # now let the "server" read everything, in order
        self.server_end.settimeout(10)
        kinds = []
        for _ in range(3):
            message, body = recv_message(self.server_end, CIPHER)
            kinds.append(message["type"])
            if message["type"] == "file":
                self.assertEqual(len(body), 3 * 1024 * 1024)
        self.assertEqual(kinds, ["file", "public", "attendees"])

    def test_file_sent_event_is_posted_only_after_the_upload_really_finished(self):
        # Hold the write back explicitly: how much a socket buffers differs per operating system.
        small = self.tmp / "small.txt"
        small.write_bytes(b"x" * 1000)
        release = threading.Event()
        real_send_frame = client_core.send_frame

        def gated(sock, payload):
            release.wait(10)
            return real_send_frame(sock, payload)

        with mock.patch("client_core.send_frame", gated):
            self.conn.send_file_in_background(small)
            with self.assertRaises(queue.Empty):  # the write has not happened yet
                self.conn.events.get(timeout=0.5)
            release.set()
            event = self.conn.events.get(timeout=5)
        self.assertEqual(event, {"type": "file_sent", "name": "small.txt", "size": 1000})
        self.server_end.settimeout(10)
        message, body = recv_message(self.server_end, CIPHER)
        self.assertEqual((message["type"], body), ("file", b"x" * 1000))

    def test_close_returns_promptly_and_says_goodbye_even_with_a_stalled_upload(self):
        big = self.tmp / "big.bin"
        big.write_bytes(os.urandom(3 * 1024 * 1024))
        self.conn.send_file(big)
        started = time.monotonic()
        self.conn.close()
        self.assertLess(time.monotonic() - started, 4.0)

    def test_close_sends_bye_when_the_connection_is_healthy(self):
        self.conn.close()
        self.server_end.settimeout(5)
        message, _ = recv_message(self.server_end, CIPHER)
        self.assertEqual(message["type"], "bye")
        with self.assertRaises(ConnectionClosed):
            recv_message(self.server_end, CIPHER)

    def test_sending_after_close_fails_with_a_clear_error(self):
        self.conn.close()
        for send in (lambda: self.conn.send_public("hi"), lambda: self.conn.send_private(["a"], "hi"),
                     self.conn.request_attendees):
            with self.assertRaisesRegex(ConnectionError, "Disconnected"):
                send()

    def test_a_dead_connection_is_reported_as_an_error_and_a_disconnect(self):
        self.conn.start_listening()
        self.server_end.close()
        time.sleep(0.2)
        try:
            self.conn.send_public("into the void")
            self.conn.send_public("again")
        except ConnectionError:
            pass  # the receiver may already have noticed
        seen = []
        deadline = time.monotonic() + 5
        while not any(e["type"] == "disconnected" for e in seen):
            self.assertLess(time.monotonic(), deadline, seen)
            try:
                seen.append(self.conn.events.get(timeout=0.2))
            except queue.Empty:
                pass
        self.assertEqual(len([e for e in seen if e["type"] == "disconnected"]), 1)


class ReceiverRobustnessTests(WatchdogTestCase):
    """Feed the receiver thread hostile or malformed server messages."""

    def setUp(self):
        self.server_end, client_end = socket.socketpair()
        self.addCleanup(self.server_end.close)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.conn = ChatConnection(
            "x", 1, CIPHER, downloads_dir=Path(self.tmp.name) / "dl", log_file=Path(self.tmp.name) / "log"
        )
        self.conn._sock = client_end
        self.addCleanup(self.conn.close)
        self.conn.start_listening()

    def feed(self, message, body=b""):
        send_message(self.server_end, CIPHER, message, body)

    def test_malformed_messages_are_ignored_and_the_client_keeps_working(self):
        for message in (
            {"type": "public"},  # no sender / text
            {"type": "public", "from": 1, "text": 2},
            {"type": "private", "from": "x"},
            {"type": "hello"},
            {"type": "hello", "user": 5, "users": "nope"},
            {"type": "left", "user": None},
            {"type": "file"},
            {"type": "error"},
            {"type": "error", "message": 7},
            {"type": "from-the-future", "anything": [1, 2, 3]},
        ):
            self.feed(message)
        self.feed({"type": "public", "from": "alice", "text": "still here"})
        event = wait_for(self.conn, of_type("public"))
        self.assertEqual((event["from"], event["text"]), ("alice", "still here"))

    def test_file_sender_and_authentication_text_cannot_forge_lines(self):
        self.feed({"type": "file", "from": "a\n[00:00] bob: hi", "name": "x.txt", "size": 1}, b"x")
        event = wait_for(self.conn, of_type("file"))
        self.assertNotIn("\n", event["from"])
        self.assertEqual(clean_display("\ud800"), "\ufffd")  # lone surrogates become U+FFFD

    def test_text_from_the_network_cannot_forge_lines(self):
        self.feed({"type": "public", "from": "mallory\n[12:00] alice", "text": "hi\n[12:01] bob: i am bob\r"})
        self.feed({"type": "private", "from": "mallory", "to": ["me\nx"], "text": "a\u2028b"})
        self.feed({"type": "hello", "user": "evil\nuser", "users": ["a\nb", "ok"]})
        self.feed({"type": "error", "message": "bad\nthing"})
        public = wait_for(self.conn, of_type("public"))
        private = wait_for(self.conn, of_type("private"))
        hello = wait_for(self.conn, of_type("hello"))
        error = wait_for(self.conn, of_type("error"))
        for text in (public["from"], public["text"], private["text"], private["to"][0],
                     hello["user"], hello["users"][0], error["message"]):
            self.assertFalse(any(c in text for c in "\n\r\u2028"), repr(text))
        self.assertEqual(hello["users"][1], "ok")

    def test_non_list_user_rosters_are_tolerated(self):
        self.feed({"type": "attendees", "users": "alice"})
        self.feed({"type": "hello", "user": "bob", "users": ["bob", 3, None, "carol"]})
        self.assertEqual(wait_for(self.conn, of_type("attendees"))["users"], [])
        self.assertEqual(wait_for(self.conn, of_type("hello"))["users"], ["bob", "carol"])

    def test_corrupt_and_hostile_files(self):
        self.feed({"type": "file", "from": "mallory", "name": "x.bin", "size": 99}, b"short")
        self.assertIn("Corrupt", wait_for(self.conn, of_type("error"))["message"])
        self.feed({"type": "file", "from": "mallory", "name": "../../evil.sh", "size": 4}, b"echo")
        event = wait_for(self.conn, of_type("file"))
        self.assertEqual(Path(event["path"]).parent, Path(self.tmp.name) / "dl")
        self.assertEqual(event["name"], "evil.sh")

    def test_unsaveable_file_reports_an_error_instead_of_crashing(self):
        (Path(self.tmp.name) / "dl").write_text("a file where the directory should be")
        self.feed({"type": "file", "from": "mallory", "name": "x.bin", "size": 1}, b"x")
        self.assertIn("Could not save", wait_for(self.conn, of_type("error"))["message"])
        self.feed({"type": "public", "from": "alice", "text": "receiver survived"})
        self.assertEqual(wait_for(self.conn, of_type("public"))["text"], "receiver survived")

    def test_server_closing_produces_a_disconnected_event(self):
        self.server_end.close()
        event = wait_for(self.conn, of_type("disconnected"))
        self.assertIn("closed", event["reason"])

    def test_undecryptable_data_produces_a_disconnected_event(self):
        self.server_end.sendall(b"\x00\x00\x00\x40" + b"x" * 64)
        event = wait_for(self.conn, of_type("disconnected"))
        self.assertIn("Protocol error", event["reason"])

    def test_deliberate_close_does_not_report_a_disconnect(self):
        self.conn.close()
        with self.assertRaises(queue.Empty):
            self.conn.events.get(timeout=0.5)

    def test_received_messages_are_logged_encrypted(self):
        self.feed({"type": "public", "from": "alice", "text": "log me"})
        self.feed({"type": "private", "from": "alice", "to": ["me"], "text": "and me"})
        wait_for(self.conn, of_type("private"))
        entries = ChatLogger(Path(self.tmp.name) / "log", CIPHER).read()
        self.assertEqual([(e["sender"], e["message"], e["message_type"]) for e in entries],
                         [("alice", "log me", "public"), ("alice", "and me", "private")])


class ClientAgainstServerTests(ServerTestCase):
    def test_the_login_timeout_is_cleared_after_a_successful_login(self):
        # AUTH_TIMEOUT must only apply to the handshake; an idle chat must not time out.
        with mock.patch.object(client_core, "AUTH_TIMEOUT", 0.4):
            alice = self.join("alice")
            time.sleep(1.2)
            seen = []
            while not alice.events.empty():
                seen.append(alice.events.get_nowait())
            self.assertFalse([e for e in seen if e["type"] == "disconnected"], seen)
            alice.send_public("still connected")  # no exception: the socket is still usable

    def test_everything_sent_and_received_is_written_to_the_encrypted_log(self):
        self.register("alice")
        self.register("bob")
        log_path = self.tmp / "alice-log.jsonl"
        alice = ChatConnection("127.0.0.1", self.server.port, self.cipher,
                               downloads_dir=self.downloads_dir("alice"), log_file=log_path)
        alice.connect()
        self._connections.append(alice)
        alice.authenticate("login", "alice", PASSWORD)
        alice.start_listening()
        wait_for(alice, of_type("hello", user="alice"))
        bob = self.join("bob")
        wait_for(alice, of_type("hello", user="bob"))

        sent_file = self.tmp / "sent.txt"
        sent_file.write_bytes(b"outgoing")
        alice.send_public("hello room")
        alice.send_private(["bob"], "hello bob")
        alice.send_file(sent_file)
        bob.send_file(sent_file)  # alice receives this one
        bob.send_public("from bob")
        wait_for(alice, of_type("public", text="from bob"))
        entries = [(e["sender"], e["message"], e["message_type"], e["recipients"])
                   for e in ChatLogger(log_path, self.cipher).read()]
        self.assertIn(("alice", "hello room", "public", []), entries)
        self.assertIn(("alice", "hello bob", "private", ["bob"]), entries)
        self.assertIn(("alice", "Sent file: sent.txt", "file", []), entries)
        self.assertIn(("bob", "Received file: sent.txt", "file", []), entries)
        self.assertIn(("bob", "from bob", "public", []), entries)
        self.assertNotIn("hello room", log_path.read_text())  # encrypted at rest

    def test_a_too_large_file_in_the_background_is_reported(self):
        alice = self.join("alice")
        huge = self.tmp / "huge.bin"
        with open(huge, "wb") as handle:
            handle.truncate(25 * 1024 * 1024 + 1)
        alice.send_file_in_background(huge)
        self.assertIn("too large", wait_for(alice, of_type("error"))["message"])

    def test_close_is_idempotent_and_says_goodbye_exactly_once(self):
        alice = self.join("alice")
        bob = self.join("bob")
        alice.close()
        alice.close()
        alice.close()
        seen = collect_until(bob, of_type("left", user="alice"))
        self.assertEqual(len([e for e in seen if e["type"] == "left"]), 1)

    def test_a_silent_server_does_not_block_the_login_forever(self):
        with socket.socket() as silent:
            silent.bind(("127.0.0.1", 0))
            silent.listen()
            conn = ChatConnection("127.0.0.1", silent.getsockname()[1], self.cipher, log_file=None)
            conn.connect()
            self._connections.append(conn)
            started = time.monotonic()
            with mock.patch.object(client_core, "AUTH_TIMEOUT", 0.3):
                with self.assertRaises(OSError):
                    conn.authenticate("login", "alice", PASSWORD)
            self.assertLess(time.monotonic() - started, 2.0)
            self.assertTrue(conn._closing.is_set())

    def test_only_an_auth_ok_reply_counts_as_success(self):
        for reply in ({"type": "public", "from": "x", "text": "y"}, {"type": "hello", "user": "x", "users": []},
                      {"type": "error", "message": "nope"}):
            a, b = socket.socketpair()
            self.addCleanup(b.close)
            conn = ChatConnection("x", 1, self.cipher, log_file=None)
            conn._sock = a
            threading.Thread(target=lambda: (recv_message(b, self.cipher), send_message(b, self.cipher, reply)),
                             daemon=True).start()
            with self.assertRaises(AuthError, msg=reply["type"]):
                conn.authenticate("login", "alice", PASSWORD)
            self.assertTrue(conn._closing.is_set())
            self.assertEqual(a.fileno(), -1)  # the socket really was closed

    def test_registration_closes_the_connection_and_auth_text_is_cleaned(self):
        a, b = socket.socketpair()
        self.addCleanup(b.close)
        conn = ChatConnection("x", 1, self.cipher, log_file=None)
        conn._sock = a
        threading.Thread(target=lambda: (recv_message(b, self.cipher),
                                         send_message(b, self.cipher, {"type": "auth_ok", "message": "done\nforged"})),
                         daemon=True).start()
        self.assertEqual(conn.authenticate("register", "alice", PASSWORD), "done forged")
        self.assertEqual(a.fileno(), -1)

    def test_an_oversized_login_reply_is_a_protocol_error(self):
        a, b = socket.socketpair()
        self.addCleanup(b.close)
        conn = ChatConnection("x", 1, self.cipher, log_file=None)
        conn._sock = a
        threading.Thread(target=lambda: (recv_message(b, self.cipher),
                                         send_message(b, self.cipher, {"type": "auth_ok", "message": "x" * 6000})),
                         daemon=True).start()
        with self.assertRaises(ProtocolError):
            conn.authenticate("login", "alice", PASSWORD)

    def test_a_failed_write_reports_the_error_and_then_the_disconnect_in_order(self):
        conn = ChatConnection("x", 1, self.cipher, log_file=None)
        a, b = socket.socketpair()
        self.addCleanup(b.close)
        conn._sock = a
        conn.username = "alice"
        conn.start_listening()  # the receiver stays blocked on the (idle) peer
        with mock.patch("client_core.send_frame", side_effect=BrokenPipeError(32, "Broken pipe")):
            conn.send_public("x")
            seen = collect_until(conn, of_type("disconnected"), timeout=5)
        kinds = [e["type"] for e in seen]
        self.assertEqual(kinds, ["error", "disconnected"])
        self.assertTrue(seen[0]["message"].startswith("Could not send"))

    def test_a_failing_sent_callback_does_not_kill_the_writer(self):
        alice = self.join("alice")
        bob = self.join("bob")
        small = self.tmp / "s.txt"
        small.write_bytes(b"x")

        def explode(_size):
            raise RuntimeError("callback bug")

        with self.assertLogs("synapse.client", level="ERROR"):
            alice.send_file(small, on_sent=explode)
            wait_for(bob, of_type("file"))
            time.sleep(0.2)
        alice.send_public("writer still alive")
        self.assertEqual(wait_for(bob, of_type("public"))["text"], "writer still alive")


if __name__ == "__main__":
    unittest.main()
