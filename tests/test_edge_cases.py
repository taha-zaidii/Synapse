"""Edge cases and failure paths that hand-run mutation testing showed were never asserted."""

import os
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import client_core
import server as server_module
from client_core import ChatConnection, save_received_file
from crypto_utils import Cipher, get_setting, read_env_file
from protocol import (
    ProtocolError,
    decode_message,
    enable_keepalive,
    sanitize_filename,
    send_message,
)
from server import ClientSession, SessionClosed, local_ip
from tests.helpers import TEST_SECRET, ServerTestCase, of_type, wait_for
from tests.watchdog import WatchdogTestCase

ROOT = Path(__file__).resolve().parent.parent
CIPHER = Cipher(TEST_SECRET)


class FileNameLimitTests(WatchdogTestCase):
    def test_limits_are_exactly_100_characters_and_200_bytes(self):
        self.assertEqual(sanitize_filename("a" * 100), "a" * 100)
        self.assertEqual(sanitize_filename("a" * 101), "a" * 100)
        self.assertEqual(sanitize_filename("\u00e9" * 100), "\u00e9" * 100)  # 100 characters, exactly 200 bytes
        self.assertEqual(sanitize_filename("\u00e9" * 101), "\u00e9" * 100)
        self.assertEqual(sanitize_filename("\U0001f680" * 50), "\U0001f680" * 50)  # 200 bytes
        self.assertEqual(sanitize_filename("\U0001f680" * 51), "\U0001f680" * 50)
        for raw in ("\U0001f680" * 60 + ".txt", "\u4e2d" * 80, "\u4e2d" * 70 + ".txt"):  # < 100 chars, > 200 bytes
            self.assertLessEqual(len(sanitize_filename(raw).encode("utf-8")), 200, raw[:5])

    def test_an_over_long_multibyte_extension_is_cut_to_100_bytes(self):
        result = sanitize_filename("a" * 30 + "." + "\U0001f680" * 45)  # the extension alone is 181 bytes
        self.assertEqual(result, "a" * 30 + "." + "\U0001f680" * 24)

    def test_a_cut_that_lands_on_a_space_leaves_no_trailing_junk(self):
        once = sanitize_filename("a" * 99 + " " + "b" * 10)
        self.assertEqual(once, "a" * 99)
        self.assertEqual(sanitize_filename(once), once)

    def test_every_reserved_device_name_is_prefixed(self):
        for name in ("prn", "AUX", "lpt1", "LPT1.txt", "com\u00b2", "COM\u00b3.txt", "lpt\u00b3", "nul", "con", "CONIN$", "conout$"):
            self.assertEqual(sanitize_filename(name), "_" + name, name)

    def test_nesting_that_fits_the_header_cap_only_ever_yields_protocol_errors(self):
        plaintext = b'{"type":"x","a":' + b"[" * 20_000 + b"]" * 20_000 + b"}\n"
        self.assertLess(plaintext.index(b"\n"), 64 * 1024)  # under the cap, so it reaches json.loads
        try:
            message, _ = decode_message(CIPHER, CIPHER.encrypt(plaintext))
        except ProtocolError:
            return
        self.assertEqual(message["type"], "x")


class EnvFileEdgeTests(WatchdogTestCase):
    def test_a_truncated_utf16_file_is_read_not_a_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_bytes(b"\xff\xfe" + "SYNAPSE_SECRET=abcdefgh\r\n".encode("utf-16-le") + b"\x00")
            self.assertEqual(read_env_file(path)["SYNAPSE_SECRET"], "abcdefgh")

    def test_an_empty_environment_variable_falls_back_to_the_file(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ):
            env_file = Path(tmp) / ".env"
            env_file.write_text("SYNAPSE_TEST_SETTING=from-file\n")
            os.environ["SYNAPSE_TEST_SETTING"] = ""
            self.assertEqual(get_setting("SYNAPSE_TEST_SETTING", env_file), "from-file")

    def test_bare_carriage_returns_separate_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_bytes(b"A=1\rB=2\rC=3")
            self.assertEqual(read_env_file(path), {"A": "1", "B": "2", "C": "3"})

    def test_commented_out_assignments_and_mismatched_quotes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("#OLD=1\nMIXED=\"abc'\nOK=\"fine\"\n")
            self.assertEqual(read_env_file(path), {"MIXED": "\"abc'", "OK": "fine"})


class RecipientLimitTests(ServerTestCase):
    def test_exactly_the_maximum_number_of_recipients_is_accepted(self):
        alice = self.join("alice")
        names = [f"user{i}" for i in range(server_module.MAX_PRIVATE_RECIPIENTS)]
        alice.send_private(names, "hi")
        self.assertTrue(wait_for(alice, of_type("error"))["message"].startswith("Not online:"))
        alice.send_private(names + ["one-too-many"], "hi")
        self.assertEqual(wait_for(alice, of_type("error"))["message"], "Choose at least one valid recipient")


class OutboxAccountingTests(WatchdogTestCase):
    """The unsent-data limit counts what is waiting, not the frame currently being written."""

    def setUp(self):
        self.a, self.b = socket.socketpair()
        self.addCleanup(self.b.close)
        self.gate, self.entered = threading.Event(), threading.Event()
        real_send_frame = server_module.send_frame

        def slow_send(sock, payload):
            self.entered.set()
            self.gate.wait(10)
            return real_send_frame(sock, payload)

        for patcher in (
            mock.patch.object(server_module, "send_frame", slow_send),
            mock.patch.object(server_module, "MAX_OUTBOX_BYTES", 1000),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.session = ClientSession(self.a, ("127.0.0.1", 2), CIPHER)
        self.addCleanup(self.session.close)
        self.addCleanup(self.gate.set)
        self.session.send_payload(b"x" * 600)  # the writer takes this one and blocks inside send_frame
        self.assertTrue(self.entered.wait(5))

    def test_the_frame_being_written_no_longer_counts_against_the_limit(self):
        self.session.send_payload(b"y" * 600)  # 600 waiting <= 1000
        self.assertFalse(self.session._closing)

    def test_exactly_the_limit_fits_one_byte_more_closes_the_session(self):
        self.session.send_payload(b"y" * 1000)
        self.assertFalse(self.session._closing)
        with self.assertRaises(BrokenPipeError):
            self.session.send_payload(b"z")
        self.assertTrue(self.session._closing)  # the session closes itself, not just its caller

    def test_a_closed_session_error_is_an_oserror(self):
        self.assertTrue(issubclass(SessionClosed, OSError))


class FinishTimerFailureTests(WatchdogTestCase):
    def test_finish_closes_cleanly_when_the_flush_timer_cannot_start(self):
        a, b = socket.socketpair()
        self.addCleanup(b.close)
        session = ClientSession(a, ("127.0.0.1", 4), CIPHER)
        self.addCleanup(session.close)
        with mock.patch.object(threading.Timer, "start", side_effect=RuntimeError("can't start new thread")):
            session.finish()  # must not raise
        self.assertTrue(session._closing)
        deadline = time.monotonic() + 3
        while a.fileno() != -1 and time.monotonic() < deadline:  # and the socket really was closed
            time.sleep(0.02)
        self.assertEqual(a.fileno(), -1)


class LocalIpTests(WatchdogTestCase):
    @staticmethod
    def probe(connect_error=None):
        probe = mock.MagicMock()
        probe.getsockname.return_value = ("10.9.8.7", 4242)
        if connect_error is not None:
            probe.connect.side_effect = connect_error
        return probe

    def test_the_route_probe_uses_a_documentation_address_and_sends_nothing(self):
        probe = self.probe()
        with mock.patch.object(server_module.socket, "socket", return_value=probe):
            self.assertEqual(local_ip(), "10.9.8.7")
        probe.connect.assert_called_once_with(("192.0.2.1", 1))
        probe.sendto.assert_not_called()
        probe.send.assert_not_called()
        probe.close.assert_called_once()

    def test_without_a_route_the_resolver_is_asked(self):
        probe = self.probe(OSError(51, "Network is unreachable"))
        with mock.patch.object(server_module.socket, "socket", return_value=probe), \
                mock.patch.object(server_module.socket, "gethostbyname", return_value="192.168.1.5"):
            self.assertEqual(local_ip(), "192.168.1.5")
        probe.close.assert_called_once()

    def test_when_nothing_works_it_answers_loopback(self):
        probe = self.probe(OSError(51, "Network is unreachable"))
        with mock.patch.object(server_module.socket, "socket", return_value=probe), \
                mock.patch.object(server_module.socket, "gethostbyname", side_effect=socket.gaierror(8, "x")):
            self.assertEqual(local_ip(), "127.0.0.1")


class BannerTests(WatchdogTestCase):
    @unittest.skipIf(os.name == "nt", "needs POSIX signals")
    def test_all_three_banner_lines_appear_immediately_on_a_pipe(self):
        import signal
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, "SYNAPSE_SECRET": TEST_SECRET}
            env.pop("PYTHONUNBUFFERED", None)
            proc = subprocess.Popen(
                [sys.executable, str(ROOT / "server.py"), "--host", "127.0.0.1", "--port", "0",
                 "--users-file", str(Path(tmp) / "users.json")],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
                preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL),
            )
            assert proc.stdout is not None and proc.stderr is not None
            # Cleanups run last-in first-out: kill the child, reap it, and only then close its pipes.
            self.addCleanup(proc.stderr.close)
            self.addCleanup(proc.stdout.close)
            self.addCleanup(proc.wait)
            self.addCleanup(proc.kill)
            lines = queue.Queue()
            threading.Thread(target=lambda: [lines.put(proc.stdout.readline()) for _ in range(3)], daemon=True).start()
            try:
                received = [lines.get(timeout=15) for _ in range(3)]
            except queue.Empty:
                self.fail("the banner is still buffered after 15 s")
            self.assertIn("Press Ctrl+C", received[2])


class ClientEdgeTests(WatchdogTestCase):
    def test_connect_survives_a_failing_tcp_nodelay(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            real = socket.create_connection(listener.getsockname())
            self.addCleanup(real.close)
            proxy = mock.MagicMock(wraps=real)
            proxy.setsockopt.side_effect = OSError(22, "Invalid argument")
            conn = ChatConnection("127.0.0.1", listener.getsockname()[1], CIPHER, log_file=None)
            with mock.patch.object(client_core.socket, "create_connection", return_value=proxy):
                conn.connect()
            self.assertIs(conn._sock, proxy)

    def test_paragraph_separators_are_cleaned(self):
        self.assertEqual(client_core.clean_display("a\u2029b\u2028c"), "a b c")

    def test_a_port_too_large_for_a_c_long_is_an_oserror_on_every_platform(self):
        with self.assertRaises(OSError):
            ChatConnection("localhost", 10 ** 30, CIPHER, log_file=None).connect()

    def test_the_sender_of_a_private_message_is_cleaned_too(self):
        a, b = socket.socketpair()
        self.addCleanup(b.close)
        conn = ChatConnection("x", 1, CIPHER, log_file=None)
        conn._sock = a
        self.addCleanup(conn.close)
        conn.start_listening()
        send_message(b, CIPHER, {"type": "private", "from": "mallory\n[12:00] alice", "to": ["me"], "text": "hi"})
        event = wait_for(conn, of_type("private"))
        self.assertFalse(any(c in event["from"] for c in "\n\r\u2028"), repr(event["from"]))

    def test_a_failed_write_shuts_down_then_closes_and_stops_writing(self):
        # shutdown() wakes a blocked recv() on Linux/macOS, close() does on Windows: both must be tried.
        class SpySocket:
            def __init__(self, sock):
                self._sock = sock
                self.calls = []

            def __getattr__(self, name):
                return getattr(self._sock, name)

            def shutdown(self, how):
                self.calls.append("shutdown")
                raise OSError(57, "Socket is not connected")  # even a failing shutdown must not skip close

            def close(self):
                self.calls.append("close")
                return self._sock.close()

        a, b = socket.socketpair()
        self.addCleanup(b.close)
        spy = SpySocket(a)
        conn = ChatConnection("x", 1, CIPHER, log_file=None)
        conn._sock = spy
        conn.username = "alice"
        conn.start_listening()
        with mock.patch("client_core.send_frame", side_effect=BrokenPipeError(32, "Broken pipe")) as send:
            conn.send_public("one")
            wait_for(conn, of_type("error"))
            deadline = time.monotonic() + 3
            while len(spy.calls) < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            time.sleep(0.2)
            self.assertEqual(send.call_count, 1)  # the writer stopped at the first failure
        self.assertEqual(spy.calls[:2], ["shutdown", "close"])


class SaveFileEdgeTests(WatchdogTestCase):
    def test_a_failed_write_leaves_no_partial_file_behind(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_open = open

            class FullDisk:
                def __init__(self, handle):
                    self.handle = handle

                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    self.handle.close()

                def write(self, data):
                    self.handle.write(b"partial")
                    raise OSError(28, "No space left on device")

            def disk_full_open(path, *args, **kwargs):
                return FullDisk(real_open(path, *args, **kwargs))

            with mock.patch("client_core.open", disk_full_open, create=True):
                with self.assertRaises(OSError):
                    save_received_file(Path(tmp), "big.bin", b"x" * 100)
            self.assertEqual(list(Path(tmp).iterdir()), [])  # neither "big.bin" nor a stray "file"

    def test_an_unencodable_name_is_reported_not_fatal_to_the_receiver(self):
        a, b = socket.socketpair()
        self.addCleanup(b.close)
        with tempfile.TemporaryDirectory() as tmp:
            conn = ChatConnection("x", 1, CIPHER, downloads_dir=Path(tmp), log_file=None)
            conn._sock = a
            self.addCleanup(conn.close)
            conn.start_listening()
            with mock.patch("client_core.save_received_file", side_effect=UnicodeEncodeError("ascii", "x", 0, 1, "bad")):
                send_message(b, CIPHER, {"type": "file", "from": "bob", "name": "x.txt", "size": 1}, b"x")
                self.assertIn("Could not save", wait_for(conn, of_type("error"))["message"])
            send_message(b, CIPHER, {"type": "public", "from": "bob", "text": "receiver still alive"})
            self.assertEqual(wait_for(conn, of_type("public"))["text"], "receiver still alive")

    def test_the_fallback_name_never_overwrites_and_restarts_its_counter(self):
        real_open = open

        def picky_open(path, *args, **kwargs):
            if Path(path).name.startswith("refused"):
                raise OSError(36, "File name too long")
            return real_open(path, *args, **kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "file").write_bytes(b"old")
            with mock.patch("client_core.open", picky_open, create=True):
                saved = save_received_file(Path(tmp), "refused.txt", b"data")
            self.assertEqual(saved.name, "file (1)")
            self.assertEqual((Path(tmp) / "file").read_bytes(), b"old")


class KeepaliveValueTests(WatchdogTestCase):
    @unittest.skipIf(os.name == "nt", "POSIX socket options")
    def test_the_documented_keepalive_timers_are_what_is_set(self):
        darwin = sys.platform == "darwin"
        options = {
            30: getattr(socket, "TCP_KEEPIDLE", None) or getattr(socket, "TCP_KEEPALIVE", 0x10 if darwin else None),
            10: getattr(socket, "TCP_KEEPINTVL", 0x101 if darwin else None),
            3: getattr(socket, "TCP_KEEPCNT", 0x102 if darwin else None),
        }
        with socket.socket() as sock:
            enable_keepalive(sock)
            for expected, option in options.items():
                self.assertEqual(sock.getsockopt(socket.IPPROTO_TCP, option), expected, hex(option))

    def test_an_unsupported_option_never_raises(self):
        sock = mock.MagicMock()

        def fail_for_tcp_options(level, *rest):
            if level == socket.IPPROTO_TCP:
                raise OSError(92, "Protocol not available")

        sock.setsockopt.side_effect = fail_for_tcp_options
        enable_keepalive(sock)  # must not raise


if __name__ == "__main__":
    unittest.main()
