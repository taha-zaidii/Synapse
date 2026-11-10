"""End-to-end tests: a real ChatServer and real ChatConnections talking over localhost."""

import contextlib
import errno
import io
import json
import os
import queue
import random
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import bcrypt

import server as server_module
from client_core import AuthError, ChatConnection
from crypto_utils import Cipher
from protocol import (
    KEEPALIVE_IDLE,
    MAX_PASSWORD_BYTES,
    ConnectionClosed,
    ProtocolError,
    recv_frame,
    recv_message,
    send_frame,
    send_message,
)
from server import (
    ChatServer,
    ClientSession,
    SessionClosed,
    UserExistsError,
    UserStore,
    UserStoreError,
    describe_reachability,
)
from tests.helpers import (
    PASSWORD,
    TEST_SECRET,
    ServerTestCase,
    collect_until,
    of_type,
    wait_for,
)
from tests.watchdog import WatchdogTestCase

ROOT = Path(__file__).resolve().parent.parent


def assert_hangs_up(testcase, sock, timeout=5):
    """The server must close this connection.  A reset counts too (Windows resets when
    the server closes a socket that still holds unread bytes; Unix sends an orderly EOF)."""
    sock.settimeout(timeout)
    try:
        data = sock.recv(10)
    except ConnectionResetError:
        return
    testcase.assertEqual(data, b"")


class AuthenticationTests(ServerTestCase):
    def test_register_then_login(self):
        self.assertEqual(self.register("alice"), "Registration successful")
        conn = self.new_connection("alice")
        self.assertEqual(conn.authenticate("login", "alice", PASSWORD), "Login successful")
        self.assertEqual(conn.username, "alice")

    def test_passwords_are_stored_as_bcrypt_hashes_never_in_clear(self):
        self.register("alice", "my very private password")
        raw = self.users_file.read_text()
        self.assertNotIn("my very private password", raw)
        stored = json.loads(raw)["alice"]
        self.assertTrue(bcrypt.checkpw(b"my very private password", stored.encode()))

    def test_wrong_password_and_unknown_user_get_the_same_generic_error(self):
        self.register("alice")
        messages = set()
        for name, password in (("alice", "wrong"), ("nobody", PASSWORD)):
            conn = self.new_connection()
            with self.assertRaises(AuthError) as ctx:
                conn.authenticate("login", name, password)
            messages.add(str(ctx.exception))
        self.assertEqual(messages, {"Invalid username or password"})

    def test_duplicate_registration_is_rejected(self):
        self.register("alice")
        with self.assertRaisesRegex(AuthError, "already exists"):
            self.register("alice", "another password")
        # ...and the original password still works
        conn = self.new_connection()
        conn.authenticate("login", "alice", PASSWORD)

    def test_invalid_registrations_are_rejected_with_a_reason(self):
        bad = [
            ("", PASSWORD, "Username"),
            ("has space", PASSWORD, "Username"),
            ("pipe|name", PASSWORD, "Username"),
            ("x" * 33, PASSWORD, "Username"),
            ("bob", "", "Password"),
            ("bob", "p" * (MAX_PASSWORD_BYTES + 1), "Password"),
        ]
        for name, password, expected in bad:
            with self.assertRaisesRegex(AuthError, expected, msg=f"{name!r}/{password!r}"):
                self.new_connection().authenticate("register", name, password)
        self.assertFalse(self.users_file.exists() and json.loads(self.users_file.read_text()))

    def test_boundary_password_lengths_work(self):
        for name, password in (("short", "x"), ("longest", "p" * MAX_PASSWORD_BYTES), ("unicode", "ü" * 36)):
            self.register(name, password)
            self.new_connection().authenticate("login", name, password)

    def test_second_login_of_the_same_user_is_rejected_until_they_leave(self):
        first = self.join("alice")
        second = self.new_connection()
        with self.assertRaisesRegex(AuthError, "already logged in"):
            second.authenticate("login", "alice", PASSWORD)
        first.close()
        # the server notices the disconnect asynchronously; allow a moment
        deadline = time.monotonic() + 5
        while True:
            try:
                self.new_connection().authenticate("login", "alice", PASSWORD)
                break
            except AuthError:
                self.assertLess(time.monotonic(), deadline, "user was never released")
                time.sleep(0.05)

    def test_simultaneous_logins_of_one_user_admit_exactly_one(self):
        self.register("alice")
        results = []

        def attempt():
            conn = self.new_connection()
            try:
                conn.authenticate("login", "alice", PASSWORD)
                results.append("ok")
            except AuthError as exc:
                results.append(str(exc))

        threads = [threading.Thread(target=attempt) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count("ok"), 1, results)

    def test_simultaneous_registrations_of_one_name_admit_exactly_one(self):
        results = []

        def attempt(i):
            try:
                self.new_connection().authenticate("register", "alice", f"password-{i}")
                results.append("ok")
            except AuthError as exc:
                results.append(str(exc))

        threads = [threading.Thread(target=attempt, args=(i,)) for i in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count("ok"), 1, results)
        self.assertEqual(list(json.loads(self.users_file.read_text())), ["alice"])

    def test_chat_before_logging_in_is_refused(self):
        conn = self.new_connection()
        send_message(conn._sock, self.cipher, {"type": "public", "text": "sneaky"})
        reply, _ = recv_message(conn._sock, self.cipher)
        self.assertEqual(reply["type"], "auth_error")
        with self.assertRaises(ConnectionClosed):
            recv_message(conn._sock, self.cipher)

    def test_unknown_auth_action_is_refused(self):
        conn = self.new_connection()
        send_message(conn._sock, self.cipher, {"type": "delete-everything", "username": "a", "password": "b"})
        reply, _ = recv_message(conn._sock, self.cipher)
        self.assertEqual(reply["type"], "auth_error")

    def test_non_string_credentials_are_refused(self):
        for username, password in ((1, "x"), ("alice", 2), (None, None), (["a"], {"b": 1})):
            conn = self.new_connection()
            send_message(conn._sock, self.cipher,
                         {"type": "register", "username": username, "password": password})
            reply, _ = recv_message(conn._sock, self.cipher)
            self.assertEqual(reply["type"], "auth_error", (username, password))

    def test_client_with_the_wrong_secret_is_dropped(self):
        conn = self.new_connection(cipher=Cipher("not-the-right-shared-secret"))
        with self.assertRaises(ProtocolError):
            conn.authenticate("register", "mallory", PASSWORD)
        self.assertFalse(self.users_file.exists() and json.loads(self.users_file.read_text()))

    def test_existing_users_json_from_the_old_format_still_works(self):
        # The original project stored {"name": "<bcrypt hash>"}; keep honouring that.
        legacy = bcrypt.hashpw(b"legacy-pass", bcrypt.gensalt(rounds=4)).decode()
        self.users_file.write_text(json.dumps({"taha": legacy}))
        server = ChatServer("127.0.0.1", 0, cipher=self.cipher, users_file=self.users_file, bcrypt_rounds=4)
        server.start()
        self.addCleanup(server.shutdown)
        conn = ChatConnection("127.0.0.1", server.port, self.cipher, log_file=None)
        conn.connect()
        self.addCleanup(conn.close)
        self.assertEqual(conn.authenticate("login", "taha", "legacy-pass"), "Login successful")


class MessagingTests(ServerTestCase):
    def test_public_message_reaches_everyone_but_the_sender(self):
        alice, bob, carol = self.join("alice"), self.join("bob"), self.join("carol")
        alice.send_public("hello everyone: 1, 2 ^ 3 | done")
        for receiver in (bob, carol):
            event = wait_for(receiver, of_type("public"))
            self.assertEqual(event["from"], "alice")
            self.assertEqual(event["text"], "hello everyone: 1, 2 ^ 3 | done")
        # the sender must not get an echo: bob's reply is the first public alice sees
        bob.send_public("reply")
        seen = collect_until(alice, of_type("public"))
        self.assertEqual([e["from"] for e in seen if e["type"] == "public"], ["bob"])

    def test_sender_name_cannot_be_spoofed(self):
        alice, bob = self.join("alice"), self.join("bob")
        send_message(alice._sock, self.cipher, {"type": "public", "from": "bob", "text": "i am bob"})
        self.assertEqual(wait_for(bob, of_type("public"))["from"], "alice")

    def test_private_message_reaches_only_its_recipients(self):
        alice, bob, carol, dave = (self.join(n) for n in ("alice", "bob", "carol", "dave"))
        alice.send_private(["bob", "carol"], "psst")
        for receiver in (bob, carol):
            event = wait_for(receiver, of_type("private"))
            self.assertEqual((event["from"], event["text"]), ("alice", "psst"))
            self.assertEqual(event["to"], ["bob", "carol"])
        # dave must see the later public message and nothing private before it
        alice.send_public("public follow-up")
        seen = collect_until(dave, of_type("public"))
        self.assertFalse([e for e in seen if e["type"] == "private"], seen)

    def test_private_message_to_an_offline_user_reports_an_error(self):
        alice = self.join("alice")
        alice.send_private(["ghost"], "anyone there?")
        event = wait_for(alice, of_type("error"))
        self.assertIn("ghost", event["message"])

    def test_private_message_to_online_and_offline_delivers_and_reports(self):
        alice, bob = self.join("alice"), self.join("bob")
        alice.send_private(["bob", "ghost"], "hi")
        self.assertEqual(wait_for(bob, of_type("private"))["text"], "hi")
        self.assertIn("ghost", wait_for(alice, of_type("error"))["message"])

    def test_private_message_with_bad_recipient_lists_is_rejected(self):
        alice = self.join("alice")
        for bad in (None, [], "bob", [1], [""], ["x" * 100], ["a"] * 101, ["bad name"], ["a\nb"], ["\x1b[2J"], ["a|b"]):
            send_message(alice._sock, self.cipher, {"type": "private", "to": bad, "text": "hi"})
            reply = wait_for(alice, of_type("error"))
            self.assertEqual(reply["message"], "Choose at least one valid recipient", bad)

    def test_duplicate_recipients_are_delivered_once(self):
        alice, bob = self.join("alice"), self.join("bob")
        alice.send_private(["bob", "bob", "bob"], "once")
        alice.send_public("marker")
        events = collect_until(bob, of_type("public"))
        self.assertEqual(len([e for e in events if e["type"] == "private"]), 1)

    def test_invalid_text_is_rejected_by_the_server(self):
        alice, bob = self.join("alice"), self.join("bob")
        for kind in ("public", "private"):
            for text in ("", "   ", "x" * 4001, None, 42):
                message = {"type": kind, "text": text}
                if kind == "private":
                    message["to"] = ["bob"]
                send_message(alice._sock, self.cipher, message)
                self.assertEqual(wait_for(alice, of_type("error"))["type"], "error", (kind, text))
        alice.send_public("still works")
        self.assertEqual(wait_for(bob, of_type("public"))["text"], "still works")

    def test_unknown_message_type_gets_an_error_and_the_connection_survives(self):
        alice, bob = self.join("alice"), self.join("bob")
        send_message(alice._sock, self.cipher, {"type": "teleport"})
        self.assertEqual(wait_for(alice, of_type("error"))["message"], "Unknown message type")
        alice.send_public("alive")
        self.assertEqual(wait_for(bob, of_type("public"))["text"], "alive")

    def test_attendee_list(self):
        alice = self.join("alice")
        self.join("bob")
        alice.request_attendees()
        self.assertEqual(wait_for(alice, of_type("attendees"))["users"], ["alice", "bob"])

    def test_join_is_announced_with_the_roster(self):
        alice = self.join("alice")
        self.join("bob")
        event = wait_for(alice, of_type("hello", user="bob"))
        self.assertEqual(event["users"], ["alice", "bob"])

    def test_leaving_is_announced_exactly_once(self):
        alice, bob, carol = self.join("alice"), self.join("bob"), self.join("carol")
        bob.close()  # sends "bye" then closes the socket; the original server announced this twice
        seen = collect_until(alice, of_type("left", user="bob"))
        self.assertEqual(seen[-1]["users"], ["alice", "carol"])
        # Anything else the server would have announced is ordered before this marker.
        carol.send_public("marker")
        later = collect_until(alice, of_type("public", text="marker"))
        self.assertFalse([e for e in later if e["type"] == "left"], later)

    def test_abrupt_disconnect_is_announced_without_a_bye(self):
        alice, bob = self.join("alice"), self.join("bob")
        bob._sock.shutdown(socket.SHUT_RDWR)  # no "bye" message, like a crash
        bob._sock.close()
        event = wait_for(alice, of_type("left", user="bob"))
        self.assertEqual(event["users"], ["alice"])

    def test_a_user_can_log_in_again_after_leaving(self):
        alice, bob = self.join("alice"), self.join("bob")
        bob.close()
        wait_for(alice, of_type("left", user="bob"))
        bob_again = self.join("bob")
        bob_again.send_public("back")
        self.assertEqual(wait_for(alice, of_type("public"))["text"], "back")


class FileTransferTests(ServerTestCase):
    def test_file_round_trip_preserves_every_byte(self):
        alice, bob, carol = self.join("alice"), self.join("bob"), self.join("carol")
        data = random.Random(7).randbytes(3 * 1024 * 1024 + 123) if hasattr(random.Random, "randbytes") \
            else os.urandom(3 * 1024 * 1024 + 123)
        data += b"\n\r\n\x00\xff"  # newlines and NULs must not confuse the framing
        source = self.tmp / "payload.bin"
        source.write_bytes(data)
        alice.send_file(source)
        for receiver, name in ((bob, "bob"), (carol, "carol")):
            event = wait_for(receiver, of_type("file"))
            self.assertEqual((event["from"], event["name"], event["size"]), ("alice", "payload.bin", len(data)))
            self.assertEqual(Path(event["path"]).read_bytes(), data)
            self.assertEqual(Path(event["path"]).parent, self.downloads_dir(name))

    def test_empty_file_is_transferred(self):
        alice, bob = self.join("alice"), self.join("bob")
        source = self.tmp / "empty.txt"
        source.write_bytes(b"")
        alice.send_file(source)
        event = wait_for(bob, of_type("file"))
        self.assertEqual(event["size"], 0)
        self.assertEqual(Path(event["path"]).read_bytes(), b"")

    def test_same_file_twice_does_not_overwrite(self):
        alice, bob = self.join("alice"), self.join("bob")
        for content in (b"first", b"second"):
            source = self.tmp / "notes.txt"
            source.write_bytes(content)
            alice.send_file(source)
        first = wait_for(bob, of_type("file"))
        second = wait_for(bob, of_type("file"))
        self.assertEqual(Path(first["path"]).name, "notes.txt")
        self.assertEqual(Path(second["path"]).name, "notes (1).txt")
        self.assertEqual(Path(first["path"]).read_bytes(), b"first")
        self.assertEqual(Path(second["path"]).read_bytes(), b"second")

    def test_hostile_file_names_are_neutralised_and_cannot_escape_downloads(self):
        alice, bob = self.join("alice"), self.join("bob")
        victim_dir = self.tmp / "outside"
        victim_dir.mkdir()
        for name in ("../../outside/pwned.txt", "..\\..\\outside\\pwned2.txt", "/etc/cron.d/evil", "CON", ""):
            send_message(alice._sock, self.cipher, {"type": "file", "name": name, "size": 3}, b"abc")
            event = wait_for(bob, of_type("file"))
            saved = Path(event["path"])
            self.assertEqual(saved.parent, self.downloads_dir("bob"), name)
            self.assertEqual(saved.read_bytes(), b"abc")
        self.assertEqual(list(victim_dir.iterdir()), [])

    def test_size_header_must_match_the_body(self):
        alice, bob = self.join("alice"), self.join("bob")
        for declared in (2, 4, -1, "3", None, True, 3.0):
            send_message(alice._sock, self.cipher, {"type": "file", "name": "x", "size": declared}, b"abc")
            self.assertEqual(wait_for(alice, of_type("error"))["type"], "error", declared)
        alice.send_public("nothing was relayed")
        seen = collect_until(bob, of_type("public"))
        self.assertFalse([e for e in seen if e["type"] == "file"], seen)

    def test_oversized_file_is_refused_and_the_connection_survives(self):
        with mock.patch.object(server_module, "MAX_FILE_SIZE", 1000):
            alice, bob = self.join("alice"), self.join("bob")
            send_message(alice._sock, self.cipher, {"type": "file", "name": "big", "size": 2000}, b"x" * 2000)
            self.assertIn("too large", wait_for(alice, of_type("error"))["message"])
            alice.send_public("alive")
            seen = collect_until(bob, of_type("public"))
            self.assertFalse([e for e in seen if e["type"] == "file"])

    def test_client_refuses_to_send_files_over_the_limit(self):
        alice = self.join("alice")
        source = self.tmp / "huge.bin"
        with open(source, "wb") as handle:
            handle.truncate(25 * 1024 * 1024 + 1)  # sparse; never read
        with self.assertRaisesRegex(ValueError, "too large"):
            alice.send_file(source)

    def test_file_sent_in_background_reports_completion(self):
        alice, bob = self.join("alice"), self.join("bob")
        source = self.tmp / "bg.txt"
        source.write_bytes(b"background")
        alice.send_file_in_background(source)
        self.assertEqual(wait_for(alice, of_type("file_sent"))["size"], 10)
        self.assertEqual(Path(wait_for(bob, of_type("file"))["path"]).read_bytes(), b"background")

    def test_background_send_of_a_missing_file_reports_an_error(self):
        alice = self.join("alice")
        alice.send_file_in_background(self.tmp / "does-not-exist")
        self.assertIn("does-not-exist", wait_for(alice, of_type("error"))["message"])


class RobustnessTests(ServerTestCase):
    def assert_server_still_works(self):
        alice, bob = self.join("probe-a"), self.join("probe-b")
        alice.send_public("still alive")
        self.assertEqual(wait_for(bob, of_type("public"))["text"], "still alive")

    def raw_socket(self):
        sock = socket.create_connection(("127.0.0.1", self.server.port), timeout=5)
        self.addCleanup(sock.close)
        return sock

    def test_garbage_bytes(self):
        for payload in (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", os.urandom(4096), b"\x00" * 10, b"\xff" * 64):
            sock = self.raw_socket()
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass  # the server's reset may already have arrived (ENOTCONN)
            sock.settimeout(5)
            try:
                while sock.recv(4096):  # the server must close the connection, not hang
                    pass
            except ConnectionResetError:
                pass  # an abrupt close is just as good
        self.assert_server_still_works()

    def test_absurd_frame_length_is_refused_without_allocating_it(self):
        sock = self.raw_socket()
        sock.sendall(struct.pack("!I", 0xFFFFFFFF) + b"junk")
        assert_hangs_up(self, sock)
        self.assert_server_still_works()

    def test_oversized_pre_login_frame_is_refused(self):
        sock = self.raw_socket()
        send_frame(sock, b"x" * 100_000)  # far above the 4 KB limit for unauthenticated clients
        assert_hangs_up(self, sock)
        self.assert_server_still_works()

    def test_truncated_frame_then_disconnect(self):
        sock = self.raw_socket()
        sock.sendall(struct.pack("!I", 500) + b"partial")
        sock.close()
        self.assert_server_still_works()

    def test_authenticated_client_sending_garbage_is_dropped_and_announced_leaving(self):
        alice, bob = self.join("alice"), self.join("bob")
        send_frame(bob._sock, b"this is not encrypted")
        wait_for(alice, of_type("left", user="bob"))
        self.assert_server_still_works()

    def test_connection_that_never_logs_in_times_out(self):
        with mock.patch.object(server_module, "AUTH_TIMEOUT", 0.3):
            sock = self.raw_socket()
            assert_hangs_up(self, sock)  # server hung up on the silent client
        self.assert_server_still_works()

    def test_many_connections_opened_and_dropped(self):
        for _ in range(60):
            sock = socket.create_connection(("127.0.0.1", self.server.port), timeout=5)
            sock.close()
        self.assert_server_still_works()

    def test_many_clients_chatting_concurrently_lose_and_corrupt_nothing(self):
        names = [f"user{i}" for i in range(8)]
        clients = {name: self.join(name) for name in names}
        per_client = 40
        errors = []

        def chatter(name):
            try:
                for i in range(per_client):
                    clients[name].send_public(f"{name}|{i}|" + "é" * (i % 7) + "x" * (i * 13))
            except Exception as exc:  # pragma: no cover - reported below
                errors.append(exc)

        threads = [threading.Thread(target=chatter, args=(name,)) for name in names]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])

        for name in names:
            expected = {(other, i) for other in names if other != name for i in range(per_client)}
            received = set()
            while received != expected:
                event = wait_for(clients[name], of_type("public"))
                sender, index, rest = event["text"].split("|", 2)
                self.assertEqual(sender, event["from"])
                self.assertEqual(rest, "é" * (int(index) % 7) + "x" * (int(index) * 13))
                received.add((sender, int(index)))

    def test_concurrent_senders_to_one_receiver_do_not_interleave_frames(self):
        sender_a, sender_b, receiver = self.join("a"), self.join("b"), self.join("r")
        blob_a, blob_b = b"A" * 400_000, b"B" * 400_000
        for blob, name in ((blob_a, "a.bin"), (blob_b, "b.bin")):
            (self.tmp / name).write_bytes(blob)
        threads = [
            threading.Thread(target=sender_a.send_file, args=(self.tmp / "a.bin",)),
            threading.Thread(target=sender_b.send_file, args=(self.tmp / "b.bin",)),
            threading.Thread(target=sender_a.send_public, args=("text while files fly",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        files = {}
        while len(files) < 2:
            event = wait_for(receiver, of_type("file"))
            files[event["name"]] = Path(event["path"]).read_bytes()
        self.assertEqual(files, {"a.bin": blob_a, "b.bin": blob_b})

    def test_a_client_that_never_reads_does_not_block_the_others(self):
        alice, bob = self.join("alice"), self.join("bob")
        # carol logs in but never reads anything, so her socket buffers fill up
        self.register("carol")
        carol = self.new_connection("carol")
        carol.authenticate("login", "carol", PASSWORD)
        big = self.tmp / "big.bin"
        big.write_bytes(os.urandom(2 * 1024 * 1024))
        started = time.monotonic()
        for _ in range(6):
            alice.send_file(big)
        self.assertLess(time.monotonic() - started, 30)
        for _ in range(6):
            self.assertEqual(wait_for(bob, of_type("file"))["size"], 2 * 1024 * 1024)
        bob.send_public("bob is not blocked either")
        self.assertEqual(wait_for(alice, of_type("public"))["text"], "bob is not blocked either")

    def test_a_client_that_falls_too_far_behind_is_disconnected(self):
        with mock.patch.object(server_module, "MAX_OUTBOX_BYTES", 1_000_000):
            alice, bob = self.join("alice"), self.join("bob")
            self.register("carol")
            carol = self.new_connection("carol")
            carol.authenticate("login", "carol", PASSWORD)  # ...and then never reads
            wait_for(bob, of_type("hello", user="carol"))
            big = self.tmp / "big.bin"
            big.write_bytes(os.urandom(300_000))
            seen = []
            for _ in range(80):
                alice.send_file(big)
                # Wait until the healthy reader has each file before sending the next, so the
                # outcome never depends on how fast the machine relays (that made an earlier
                # version of this test flaky).
                seen += collect_until(bob, of_type("file"))
                if any(e["type"] == "left" and e["user"] == "carol" for e in seen):
                    break
            else:
                seen += collect_until(bob, of_type("left", user="carol"), timeout=20)
            self.assertFalse([e for e in seen if e["type"] == "disconnected"], "bob must stay connected")
            alice.send_public("the rest of the room carries on")
            self.assertEqual(
                wait_for(bob, of_type("public"))["text"], "the rest of the room carries on"
            )

    def test_shutdown_disconnects_clients(self):
        alice = self.join("alice")
        self.server.shutdown()
        event = wait_for(alice, of_type("disconnected"))
        self.assertTrue(event["reason"])
        self.server.shutdown()  # idempotent


class AcceptLoopTests(ServerTestCase):
    """One bad connection must never end the loop that serves everybody else."""

    _probes = 0

    def assert_server_still_works(self):
        AcceptLoopTests._probes += 1
        tag = AcceptLoopTests._probes
        alice, bob = self.join(f"probe-a{tag}"), self.join(f"probe-b{tag}")
        alice.send_public("still alive")
        self.assertEqual(wait_for(bob, of_type("public"))["text"], "still alive")

    def test_a_failure_while_setting_up_one_connection_does_not_end_the_accept_loop(self):
        # macOS makes setsockopt() fail with EINVAL on a connection the peer already reset;
        # that used to kill the accept thread, so the server silently stopped taking clients.
        for failure in (OSError(errno.EINVAL, "Invalid argument"), RuntimeError("can't start new thread")):
            with self.subTest(failure=type(failure).__name__):
                original = ChatServer._start_session
                calls = []

                def flaky(server, sock, address, _original=original, _failure=failure):
                    calls.append(address)
                    if len(calls) == 1:
                        raise _failure
                    return _original(server, sock, address)

                with mock.patch.object(ChatServer, "_start_session", flaky), \
                        self.assertLogs("synapse.server", level="DEBUG") as logs:
                    doomed = socket.create_connection(("127.0.0.1", self.server.port), timeout=5)
                    self.addCleanup(doomed.close)
                    assert_hangs_up(self, doomed)
                    self.assertEqual(len(calls), 1)
                    self.assert_server_still_works()
                    self.assertGreaterEqual(len(calls), 2)
                self.assertTrue(any("during setup" in line or "Could not start" in line for line in logs.output))
                self.assertTrue(self.server._accept_thread.is_alive())

    def test_connections_reset_before_they_are_accepted_do_not_hurt_the_server(self):
        linger_reset = struct.pack("ii", 1, 0)  # close() sends RST instead of FIN
        for _ in range(150):
            sock = socket.socket()
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger_reset)
            sock.connect(("127.0.0.1", self.server.port))
            sock.close()
        self.assertTrue(self.server._accept_thread.is_alive())
        self.assert_server_still_works()


class HandshakeTests(ServerTestCase):
    def test_the_login_deadline_cannot_be_dodged_by_dripping_bytes(self):
        # A client that sends one byte every 100 ms never lets a per-read timeout expire,
        # but must still be cut off once the whole handshake has taken too long.
        with mock.patch.object(server_module, "AUTH_TIMEOUT", 0.6):
            sock = socket.create_connection(("127.0.0.1", self.server.port), timeout=5)
            self.addCleanup(sock.close)
            sock.setblocking(False)
            started = time.monotonic()
            sock.send(struct.pack("!I", 100))  # promises a 100-byte frame...
            closed_after = None
            while time.monotonic() - started < 6:
                try:
                    sock.send(b"x")  # ...and delivers it one byte at a time
                    time.sleep(0.1)
                    if sock.recv(1) == b"":
                        closed_after = time.monotonic() - started
                        break
                except BlockingIOError:
                    continue
                except OSError:  # reset or broken pipe: the server cut us off
                    closed_after = time.monotonic() - started
                    break
        self.assertIsNotNone(closed_after, "the server never cut off the dripping client")
        self.assertLess(closed_after, 3)

    def test_a_normal_login_is_not_affected_by_the_deadline_afterwards(self):
        with mock.patch.object(server_module, "AUTH_TIMEOUT", 0.5):
            alice = self.join("alice")
            time.sleep(1.2)  # well past the handshake deadline
            bob = self.join("bob")
            alice.send_public("still connected after the deadline")
            self.assertEqual(wait_for(bob, of_type("public"))["text"], "still connected after the deadline")


class MessageHygieneTests(ServerTestCase):
    def test_line_breaks_and_control_characters_are_refused(self):
        alice, bob = self.join("alice"), self.join("bob")
        forged = "hi\n[12:00] bob: i am bob"
        for kind in ("public", "private"):
            for text in (forged, "x\r\ny", "tab\there", "a\u2028b", "nul\x00", "esc\x1b[2J"):
                message = {"type": kind, "text": text}
                if kind == "private":
                    message["to"] = ["bob"]
                send_message(alice._sock, self.cipher, message)
                reply = wait_for(alice, of_type("error"))
                self.assertIn("control characters", reply["message"], (kind, text))
        alice.send_public("clean")
        seen = collect_until(bob, of_type("public"))
        self.assertEqual([e["text"] for e in seen if e["type"] in ("public", "private")], ["clean"])

    def test_pasted_multi_line_text_is_flattened_by_the_client(self):
        alice, bob = self.join("alice"), self.join("bob")
        alice.send_public("line one\nline two\r\n\tindented")
        self.assertEqual(wait_for(bob, of_type("public"))["text"], "line one line two   indented")
        alice.send_private(["bob"], "a\nb")
        self.assertEqual(wait_for(bob, of_type("private"))["text"], "a b")

    def test_a_message_with_a_lone_surrogate_drops_the_sender_not_the_server(self):
        alice, bob = self.join("alice"), self.join("bob")
        send_frame(bob._sock, self.cipher.encrypt(b'{"type":"public","text":"\\ud800"}\n'))
        wait_for(alice, of_type("left", user="bob"))
        self.assertEqual(alice.events.qsize(), 0)
        alice.send_public("server is fine")
        carol = self.join("carol")
        alice.send_public("and still relays")
        self.assertEqual(wait_for(carol, of_type("public"))["text"], "and still relays")

    def test_absurdly_nested_json_cannot_hurt_the_server(self):
        # Depending on the Python version this is rejected (the sender is dropped) or parsed
        # as an ordinary message; either way the server and everyone else must carry on.
        alice, bob = self.join("alice"), self.join("bob")
        deep = b'{"type":"public","text":"x","extra":' + b"[" * 100_000 + b"]" * 100_000 + b"}\n"
        send_frame(bob._sock, self.cipher.encrypt(deep))
        carol = self.join("carol")  # a brand-new login still works
        alice.send_public("still fine")
        self.assertEqual(wait_for(carol, of_type("public"))["text"], "still fine")


class LifecycleTests(ServerTestCase):
    def test_roster_updates_arrive_in_order_under_concurrent_joins_and_leaves(self):
        names = [f"u{i:02d}" for i in range(16)]
        observer = self.join("observer")
        conns = {}

        def join(name):
            conns[name] = self.join(name)

        threads = [threading.Thread(target=join, args=(name,)) for name in names]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(conns), len(names))

        leavers = names[::2]
        threads = [threading.Thread(target=conns[name].close) for name in leavers]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        expected = sorted(["observer"] + [n for n in names if n not in leavers])

        for who in [observer] + [conns[n] for n in names if n not in leavers]:
            left_seen = set()
            roster_events = []

            def note(event):
                if event["type"] in ("hello", "left"):
                    roster_events.append(event)
                    if event["type"] == "left":
                        left_seen.add(event["user"])
                return left_seen >= set(leavers)

            collect_until(who, note, timeout=15)
            time.sleep(0.2)  # give any straggler a chance to arrive (and betray an ordering bug)
            while True:
                try:
                    event = who.events.get_nowait()
                except queue.Empty:
                    break
                if event["type"] in ("hello", "left"):
                    roster_events.append(event)
            self.assertEqual(roster_events[-1]["users"], expected)

    def test_replies_queued_for_a_leaving_client_are_not_cut_short(self):
        # Clients pipeline requests and then half-close; the server must still deliver every
        # reply it queued, even while other clients disconnect at the same moment.
        text = "x" * 3500
        for round_ in range(3):
            clients = []
            for i in range(8):
                name = f"g{round_}{i}"
                self.register(name)
                conn = self.new_connection(name)
                conn.authenticate("login", name, PASSWORD)
                clients.append((name, conn))
            for name, conn in clients:
                for _ in range(30):
                    send_message(conn._sock, self.cipher, {"type": "private", "to": [name], "text": text})
                conn._sock.shutdown(socket.SHUT_WR)
            for name, conn in clients:
                conn._sock.settimeout(15)
                replies = 0
                while True:
                    try:
                        message, _ = recv_message(conn._sock, self.cipher)
                    except ConnectionClosed:
                        break
                    if message["type"] == "private":
                        replies += 1
                self.assertEqual(replies, 30, (round_, name))

    def test_a_leaving_client_that_stops_reading_is_closed_after_the_flush_timeout(self):
        with mock.patch.object(server_module, "FLUSH_TIMEOUT", 0.5):
            alice = self.join("alice")
            self.register("carol")
            carol = self.new_connection("carol")
            carol.authenticate("login", "carol", PASSWORD)  # never reads
            wait_for(alice, of_type("hello", user="carol"))
            with self.server._lock:
                session = self.server._sessions["carol"]
            big = self.tmp / "big.bin"
            big.write_bytes(os.urandom(2 * 1024 * 1024))
            for _ in range(12):  # far more than the socket buffers can hold
                alice.send_file(big)
            deadline = time.monotonic() + 15
            while session._pending_bytes == 0:  # the writer is now stuck on a full socket
                self.assertLess(time.monotonic(), deadline, "nothing was ever queued for carol")
                time.sleep(0.05)
            send_message(carol._sock, self.cipher, {"type": "bye"})
            deadline = time.monotonic() + 10
            while session.sock.fileno() != -1:
                self.assertLess(time.monotonic(), deadline, "the stalled leaving client was never closed")
                time.sleep(0.05)

    def test_a_session_that_is_finishing_is_not_hard_closed_by_later_broadcasts(self):
        # Another user's leave broadcast used to call close() on a session that was still
        # flushing its queue, discarding data finish() had promised to deliver.
        self.join("alice")
        with self.server._lock:
            session = self.server._sessions["alice"]
        session.finish()
        with mock.patch.object(session, "close") as close:
            self.server._deliver([session], b"x" * 40)
        close.assert_not_called()

    def test_a_session_that_overflows_is_still_closed_by_a_broadcast(self):
        self.join("alice")
        with self.server._lock:
            session = self.server._sessions["alice"]
        with mock.patch.object(server_module, "MAX_OUTBOX_BYTES", 10):
            with mock.patch.object(session, "close") as close:
                self.server._deliver([session], b"x" * 40)
        close.assert_called()

    def test_graceful_leave_still_announces_exactly_once_and_frees_the_name(self):
        alice, bob = self.join("alice"), self.join("bob")
        bob.close()
        seen = collect_until(alice, of_type("left", user="bob"))
        self.assertEqual(len([e for e in seen if e["type"] == "left"]), 1)
        again = self.join("bob")
        again.send_public("back")
        self.assertEqual(wait_for(alice, of_type("public"))["text"], "back")


class ProtocolEnforcementTests(ServerTestCase):
    """Behaviour the audit's mutation testing showed was never asserted."""

    def raw_login(self, name):
        self.register(name)
        sock = socket.create_connection(("127.0.0.1", self.server.port), timeout=5)
        self.addCleanup(sock.close)
        send_message(sock, self.cipher, {"type": "login", "username": name, "password": PASSWORD})
        reply, _ = recv_message(sock, self.cipher)
        self.assertEqual(reply["type"], "auth_ok")
        return sock

    def test_the_relayed_file_name_is_sanitised_by_the_server(self):
        alice = self.join("alice")
        raw = self.raw_login("rawbob")  # no client-side sanitising in the way
        send_message(alice._sock, self.cipher, {"type": "file", "name": "../../evil\u202etxt.exe", "size": 1}, b"x")
        while True:
            message, _ = recv_message(raw, self.cipher)
            if message["type"] == "file":
                break
        self.assertEqual(message["name"], "evil_txt.exe")

    def test_a_boolean_size_is_refused(self):
        alice, bob = self.join("alice"), self.join("bob")
        send_message(alice._sock, self.cipher, {"type": "file", "name": "x", "size": True}, b"x")
        self.assertIn("size", wait_for(alice, of_type("error"))["message"])
        alice.send_public("marker")
        self.assertFalse([e for e in collect_until(bob, of_type("public")) if e["type"] == "file"])

    def test_the_session_is_not_ready_when_auth_ok_is_queued(self):
        self.register("alice")
        seen = []
        original = ClientSession.send

        def spy(session, message, body=b""):
            if message.get("message") == "Login successful":
                seen.append(session.ready)
            return original(session, message, body)

        with mock.patch.object(ClientSession, "send", spy):
            self.new_connection().authenticate("login", "alice", PASSWORD)
        self.assertEqual(seen, [False])

    def test_an_oversized_registration_before_login_is_refused(self):
        conn = self.new_connection()
        send_message(conn._sock, self.cipher,
                     {"type": "register", "username": "padded", "password": PASSWORD, "pad": "x" * 10_000})
        with self.assertRaises((ConnectionClosed, ConnectionResetError)):
            recv_message(conn._sock, self.cipher)
        self.assertFalse(self.users_file.exists() and json.loads(self.users_file.read_text()))

    def test_a_header_over_the_size_cap_is_refused_even_after_login(self):
        alice, bob = self.join("alice"), self.join("bob")
        send_message(bob._sock, self.cipher, {"type": "public", "text": "hi", "pad": "x" * 70_000})
        wait_for(alice, of_type("left", user="bob"))

    def test_huge_integers_cannot_stall_the_server(self):
        alice, bob = self.join("alice"), self.join("bob")
        started = time.monotonic()
        send_frame(bob._sock, self.cipher.encrypt(b'{"type":"file","name":"x","size":' + b"9" * 60_000 + b"}\n"))
        wait_for(alice, of_type("left", user="bob"))
        self.assertLess(time.monotonic() - started, 3.0)
        carol = self.join("carol")  # a new login still works, and nobody else was affected
        alice.send_public("server is responsive")
        self.assertEqual(wait_for(carol, of_type("public"))["text"], "server is responsive")

    def test_private_message_and_file_senders_cannot_be_spoofed(self):
        alice, bob = self.join("alice"), self.join("bob")
        send_message(alice._sock, self.cipher, {"type": "private", "from": "admin", "to": ["bob"], "text": "hi"})
        self.assertEqual(wait_for(bob, of_type("private"))["from"], "alice")
        send_message(alice._sock, self.cipher, {"type": "file", "from": "admin", "name": "a.txt", "size": 1}, b"x")
        self.assertEqual(wait_for(bob, of_type("file"))["from"], "alice")

    def test_unexpected_errors_in_a_handler_are_logged_and_the_client_dropped(self):
        self.register("alice")
        with mock.patch.object(ChatServer, "_chat_loop", side_effect=RuntimeError("boom")), \
                self.assertLogs("synapse.server", level="ERROR"):
            conn = self.new_connection()
            conn.authenticate("login", "alice", PASSWORD)
            conn.start_listening()
            wait_for(conn, of_type("disconnected"))

    def test_sessions_that_are_not_ready_are_invisible(self):
        alice = self.join("alice")
        ghost = mock.Mock()
        ghost.ready = False
        ghost.username = "ghost"
        with self.server._lock:
            self.server._sessions["ghost"] = ghost
        self.addCleanup(lambda: self.server._sessions.pop("ghost", None))
        with self.server._lock:
            self.assertEqual(self.server._roster_locked(), ["alice"])
        send_message(alice._sock, self.cipher, {"type": "private", "to": ["ghost"], "text": "hi"})
        self.assertIn("Not online: ghost", wait_for(alice, of_type("error"))["message"])
        alice.send_public("marker")  # a broadcast must skip the ghost too
        self.server._broadcast({"type": "public", "from": "x", "text": "y"})
        ghost.send_payload.assert_not_called()

    def test_the_not_online_error_goes_only_to_the_sender(self):
        alice, bob = self.join("alice"), self.join("bob")
        alice.send_private(["nobody"], "hi")
        wait_for(alice, of_type("error"))
        alice.send_public("marker")
        self.assertFalse([e for e in collect_until(bob, of_type("public")) if e["type"] == "error"])

    def test_roster_broadcasts_are_queued_while_holding_the_lock(self):
        calls = []
        original = ChatServer._broadcast_locked

        def spy(server, message, *args, **kwargs):
            calls.append((message["type"], server._lock.locked()))
            return original(server, message, *args, **kwargs)

        with mock.patch.object(ChatServer, "_broadcast_locked", spy):
            alice, bob = self.join("alice"), self.join("bob")
            bob.close()
            wait_for(alice, of_type("left", user="bob"))
        self.assertEqual({kind for kind, _ in calls}, {"hello", "left"})
        self.assertTrue(all(locked for _, locked in calls), calls)

    def test_a_login_with_a_non_string_username_gets_an_auth_error(self):
        conn = self.new_connection()
        send_message(conn._sock, self.cipher, {"type": "login", "username": ["a"], "password": "x"})
        reply, _ = recv_message(conn._sock, self.cipher)
        self.assertEqual(reply["type"], "auth_error")

    def test_the_duplicate_login_check_is_atomic(self):
        # Widen the race window: if the check and the reservation were not one locked step,
        # several of these logins would all see "not online yet" and succeed.
        self.register("alice")

        class SlowDict(dict):
            def __contains__(self, key):
                found = dict.__contains__(self, key)
                time.sleep(0.05)
                return found

        with self.server._lock:
            self.server._sessions = SlowDict(self.server._sessions)
        results = []

        def attempt():
            try:
                self.new_connection().authenticate("login", "alice", PASSWORD)
                results.append("ok")
            except AuthError as exc:
                results.append(str(exc))

        threads = [threading.Thread(target=attempt) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count("ok"), 1, results)


class ClientSessionTests(WatchdogTestCase):
    """ClientSession on its own, over a socketpair."""

    def setUp(self):
        from crypto_utils import Cipher as _Cipher
        self.a, self.b = socket.socketpair()
        self.addCleanup(self.b.close)
        self.session = ClientSession(self.a, ("127.0.0.1", 1), _Cipher(TEST_SECRET))
        self.addCleanup(self.session.close)

    def writer_threads(self):
        return [t for t in threading.enumerate() if t.name == "synapse-writer-1"]

    def test_finish_stops_accepting_new_data(self):
        self.session.finish()
        with self.assertRaises(SessionClosed):
            self.session.send_payload(b"x")
        self.assertTrue(self.session._closing)

    def test_close_marks_the_session_closing_and_ends_the_writer_thread(self):
        self.session.close()
        self.assertTrue(self.session._closing)
        with self.assertRaises(SessionClosed):
            self.session.send_payload(b"x")
        for thread in self.writer_threads():
            thread.join(2)
            self.assertFalse(thread.is_alive())

    def test_finish_twice_creates_only_one_flush_timer(self):
        with mock.patch.object(server_module.threading, "Timer", wraps=server_module.threading.Timer) as timer:
            self.session.finish()
            self.session.finish()
        self.assertEqual(timer.call_count, 1)

    def test_a_dead_writer_leaves_no_timer_behind(self):
        # If the connection already failed there is nothing to flush, so no 10 s timer thread
        # may be started (and it must not keep the session alive).
        with mock.patch.object(server_module, "send_frame", side_effect=BrokenPipeError("peer gone")):
            self.session.send_payload(b"x" * 100)  # the writer fails on this and exits
            for thread in self.writer_threads():
                thread.join(3)
        deadline = time.monotonic() + 3
        while not self.session._writer_done:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        with mock.patch.object(server_module.threading, "Timer") as timer:
            self.session.finish()
        timer.assert_not_called()
        self.assertIsNone(self.session._flush_timer)

    def test_queued_data_is_delivered_before_a_finish_closes_the_socket(self):
        frames = [b"first", b"second" * 1000, b"third"]
        for frame in frames:
            self.session.send_payload(frame)
        self.session.finish()
        self.b.settimeout(5)
        received = [recv_frame(self.b) for _ in frames]
        self.assertEqual(received, frames)
        with self.assertRaises(ConnectionClosed):
            recv_frame(self.b)


class SocketOptionTests(ServerTestCase):
    def test_accepted_and_client_sockets_have_nodelay_and_short_keepalive(self):
        alice = self.join("alice")
        with self.server._lock:
            session = self.server._sessions["alice"]
        idle_option = getattr(socket, "TCP_KEEPIDLE", None) or getattr(socket, "TCP_KEEPALIVE", None)
        for sock in (session.sock, alice._sock):
            self.assertTrue(sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
            self.assertTrue(sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE))
            if idle_option is not None and os.name != "nt":
                self.assertEqual(sock.getsockopt(socket.IPPROTO_TCP, idle_option), KEEPALIVE_IDLE)

    @unittest.skipIf(os.name == "nt", "SO_REUSEADDR means something else on Windows")
    def test_the_listening_socket_can_be_rebound_immediately(self):
        self.assertTrue(self.server._listener.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR))

    def test_port_65536_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            server_module.parse_args(["--port", "65536"])
        self.assertEqual(server_module.parse_args(["--port", "65535"]).port, 65535)
        self.assertEqual(server_module.parse_args(["--port", "0"]).port, 0)


class ShutdownTests(ServerTestCase):
    def test_shutdown_is_quick_and_stops_the_accept_thread(self):
        self.join("alice")
        started = time.monotonic()
        self.server.shutdown()
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertFalse(self.server._accept_thread.is_alive())

    def test_a_healthy_client_closes_quickly_and_its_writer_ends(self):
        alice = self.join("alice")
        started = time.monotonic()
        alice.close()
        self.assertLess(time.monotonic() - started, 0.8)
        alice._writer.join(1)
        self.assertFalse(alice._writer.is_alive())


class LoggingTests(ServerTestCase):
    def test_passwords_never_appear_in_logs_or_output(self):
        secret_password = "Tr0ub4dor&3-very-secret"
        out, err = io.StringIO(), io.StringIO()
        with self.assertLogs("synapse.server", level="DEBUG") as logs, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.register("alice", secret_password)
            self.join("bob", secret_password)
            for _ in range(2):  # a failed login and a duplicate login
                with self.assertRaises(AuthError):
                    self.new_connection().authenticate("login", "alice", secret_password + "x")
            with self.assertRaises(AuthError):
                self.new_connection().authenticate("login", "bob", secret_password)
        everything = "\n".join(logs.output) + out.getvalue() + err.getvalue()
        self.assertNotIn(secret_password, everything)
        self.assertIn("Registered new user 'alice'", everything)

    def test_log_lines_cannot_be_forged_through_usernames(self):
        with self.assertLogs("synapse.server", level="INFO") as logs:
            with self.assertRaises(AuthError):
                self.new_connection().authenticate("login", "evil\nFAKE LOG LINE", "x")
        self.assertEqual(len(logs.output), 1)
        self.assertNotIn("\nFAKE LOG LINE", logs.output[0])


class UserStoreTests(WatchdogTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "data" / "users.json"

    def test_persistence_and_verification(self):
        store = UserStore(self.path, rounds=4)
        store.register("alice", "pw-one")
        reloaded = UserStore(self.path, rounds=4)
        self.assertTrue(reloaded.verify("alice", "pw-one"))
        self.assertFalse(reloaded.verify("alice", "pw-two"))
        self.assertFalse(reloaded.verify("bob", "pw-one"))

    def test_duplicate_registration(self):
        store = UserStore(self.path, rounds=4)
        store.register("alice", "pw")
        with self.assertRaises(UserExistsError):
            store.register("alice", "pw2")

    def test_corrupt_database_is_reported_not_overwritten(self):
        self.path.parent.mkdir(parents=True)
        for content in ("{not json", "[1, 2]", '{"alice": 5}', ""):
            self.path.write_text(content)
            with self.assertRaises(UserStoreError):
                UserStore(self.path, rounds=4)
            self.assertEqual(self.path.read_text(), content)

    def test_a_failed_write_leaves_neither_a_temp_file_nor_a_database(self):
        store = UserStore(self.path, rounds=4)
        with mock.patch("server.os.replace", side_effect=OSError("disk exploded")):
            with self.assertRaises(OSError):
                store.register("alice", "pw")
        self.assertEqual([p.name for p in self.path.parent.iterdir()], [])
        store.register("alice", "pw")  # and a retry works

    def test_database_with_a_byte_order_mark_is_accepted(self):
        self.path.parent.mkdir(parents=True)
        hashed = bcrypt.hashpw(b"pw", bcrypt.gensalt(rounds=4)).decode()
        self.path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"alice": hashed}).encode())
        self.assertTrue(UserStore(self.path, rounds=4).verify("alice", "pw"))

    def test_malformed_stored_hash_fails_closed(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps({"alice": "not-a-bcrypt-hash"}))
        self.assertFalse(UserStore(self.path, rounds=4).verify("alice", "anything"))

    def test_failed_save_does_not_leave_the_user_registered(self):
        store = UserStore(self.path, rounds=4)
        with mock.patch.object(UserStore, "_save_locked", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                store.register("alice", "pw")
        self.assertFalse(store.verify("alice", "pw"))
        store.register("alice", "pw")  # and the name is still available

    def test_no_temporary_files_are_left_behind(self):
        store = UserStore(self.path, rounds=4)
        for i in range(5):
            store.register(f"user{i}", "pw")
        self.assertEqual([p.name for p in self.path.parent.iterdir()], ["users.json"])

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_database_is_not_world_readable(self):
        UserStore(self.path, rounds=4).register("alice", "pw")
        self.assertEqual(self.path.stat().st_mode & 0o077, 0)


class CommandLineTests(WatchdogTestCase):
    def test_help_and_bad_arguments(self):
        with contextlib.redirect_stderr(io.StringIO()):
            for argv in (["--port", "abc"], ["--port", "70000"], ["--bogus"]):
                with self.assertRaises(SystemExit) as ctx:
                    server_module.parse_args(argv)
                self.assertEqual(ctx.exception.code, 2)
        args = server_module.parse_args([])
        self.assertEqual((args.host, args.port), ("0.0.0.0", 1535))

    def test_bad_port_message_does_not_leak_internal_names(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            server_module.parse_args(["--port", "abc"])
        self.assertIn("invalid port value", stderr.getvalue())
        self.assertNotIn("_port_number", stderr.getvalue())

    def test_the_address_hint_matches_how_the_server_was_started(self):
        with mock.patch.object(server_module, "local_ip", return_value="192.168.1.5"):
            everywhere = describe_reachability("0.0.0.0", 1535)
        self.assertEqual(everywhere, "Clients on your network can connect to 192.168.1.5:1535")
        with mock.patch.object(server_module, "local_ip", return_value="127.0.0.1"):  # no LAN address
            isolated = describe_reachability("0.0.0.0", 1535)
        self.assertIn("No network address found", isolated)
        self.assertIn("127.0.0.1:1535", isolated)
        self.assertNotIn("on your network", isolated)
        local_only = describe_reachability("127.0.0.1", 1535)
        self.assertIn("Only clients on this machine", local_only)
        self.assertNotIn("network", local_only)
        self.assertEqual(describe_reachability("192.168.1.20", 9000), "Clients can connect to 192.168.1.20:9000")

    def test_missing_secret_is_a_clear_error_not_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            # run a copy of the sources from a directory that has no .env file
            for name in ("server.py", "crypto_utils.py", "protocol.py"):
                (Path(tmp) / name).write_bytes((ROOT / name).read_bytes())
            env = {k: v for k, v in os.environ.items() if k != "SYNAPSE_SECRET"}
            result = subprocess.run(
                [sys.executable, str(Path(tmp) / "server.py"), "--port", "0"],
                capture_output=True, text=True, timeout=30, env=env, cwd=tmp,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("SYNAPSE_SECRET", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_port_in_use_is_a_clear_error(self):
        with socket.socket() as blocker:
            blocker.bind(("127.0.0.1", 0))
            blocker.listen()
            port = blocker.getsockname()[1]
            with tempfile.TemporaryDirectory() as tmp:
                env = {**os.environ, "SYNAPSE_SECRET": TEST_SECRET}
                result = subprocess.run(
                    [sys.executable, str(ROOT / "server.py"), "--host", "127.0.0.1", "--port", str(port),
                     "--users-file", str(Path(tmp) / "u.json")],
                    capture_output=True, text=True, timeout=30, env=env,
                )
        self.assertEqual(result.returncode, 1)
        self.assertIn("cannot listen", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    @unittest.skipIf(os.name == "nt", "needs POSIX signals")
    def test_server_process_runs_serves_clients_and_stops_on_sigint(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Deliberately NOT "python -u": with redirected output (a pipe, a file, a container log)
            # Python block-buffers print(), and the banner must still appear immediately.
            env = {**os.environ, "SYNAPSE_SECRET": TEST_SECRET}
            env.pop("PYTHONUNBUFFERED", None)
            proc = subprocess.Popen(
                [sys.executable, str(ROOT / "server.py"), "--host", "127.0.0.1", "--port", "0",
                 "--users-file", str(Path(tmp) / "users.json")],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
                # a test runner started from a background job inherits an *ignored* SIGINT
                preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL),
            )
            assert proc.stdout is not None and proc.stderr is not None
            # Cleanups run last-in first-out: kill the child BEFORE closing its pipes, otherwise
            # closing stdout would wait for a reader thread that is blocked on that very pipe.
            self.addCleanup(proc.stderr.close)
            self.addCleanup(proc.stdout.close)
            self.addCleanup(proc.kill)
            banner = queue.Queue()
            threading.Thread(target=lambda: banner.put(proc.stdout.readline()), daemon=True).start()
            try:
                first_line = banner.get(timeout=15)
            except queue.Empty:
                self.fail("the server's banner did not appear within 15 s: its output is block-buffered")
            self.assertIn("listening on 127.0.0.1:", first_line)
            port = int(first_line.strip().rsplit(":", 1)[1])
            cipher = Cipher(TEST_SECRET)
            for action in ("register", "login"):
                conn = ChatConnection("127.0.0.1", port, cipher, log_file=None)
                conn.connect()
                self.addCleanup(conn.close)
                self.assertTrue(conn.authenticate(action, "cli-user", PASSWORD))
            proc.send_signal(signal.SIGINT)
            self.assertEqual(proc.wait(timeout=15), 0)
            self.assertTrue((Path(tmp) / "users.json").exists())


if __name__ == "__main__":
    unittest.main()
