import json
import socket
import struct
import sys
import threading
import time
import tracemalloc
import unicodedata
import unittest

from crypto_utils import Cipher
from protocol import (
    MAX_FILENAME_BYTES,
    MAX_FILENAME_LENGTH,
    MAX_HEADER_BYTES,
    MAX_PASSWORD_BYTES,
    MAX_TEXT_LENGTH,
    MAX_USERNAME_LENGTH,
    ConnectionClosed,
    ProtocolError,
    decode_message,
    enable_keepalive,
    encode_message,
    recv_exact,
    recv_frame,
    recv_message,
    sanitize_filename,
    send_frame,
    send_message,
    validate_password,
    validate_text,
    validate_username,
)
from tests.watchdog import WatchdogTestCase


class SocketPairCase(WatchdogTestCase):
    def setUp(self):
        self.a, self.b = socket.socketpair()
        self.a.settimeout(5)
        self.b.settimeout(5)
        self.addCleanup(self.a.close)
        self.addCleanup(self.b.close)
        self.cipher = Cipher("protocol-test-secret")


class FramingTests(SocketPairCase):
    def test_frame_round_trip(self):
        for payload in (b"", b"x", b"hello", bytes(range(256)) * 400):
            # send from a thread: a socketpair's buffer is smaller than the larger payloads
            sender = threading.Thread(target=send_frame, args=(self.a, payload))
            sender.start()
            self.assertEqual(recv_frame(self.b), payload)
            sender.join()

    def test_frames_that_arrive_coalesced_are_split_correctly(self):
        data = b"".join(struct.pack("!I", len(p)) + p for p in (b"one", b"", b"three!"))
        self.a.sendall(data)  # all three frames in a single TCP segment
        self.assertEqual([recv_frame(self.b) for _ in range(3)], [b"one", b"", b"three!"])

    def test_frame_that_arrives_one_byte_at_a_time(self):
        data = struct.pack("!I", 5) + b"slow!"
        for index in range(len(data)):
            self.a.sendall(data[index:index + 1])
        self.assertEqual(recv_frame(self.b), b"slow!")

    def test_large_frame_is_reassembled(self):
        payload = bytes(range(256)) * 20_000  # ~5 MB
        sender = threading.Thread(target=send_frame, args=(self.a, payload))
        sender.start()
        self.assertEqual(recv_frame(self.b), payload)
        sender.join()

    def test_clean_close_at_frame_boundary(self):
        self.a.close()
        with self.assertRaises(ConnectionClosed):
            recv_frame(self.b)

    def test_close_in_the_middle_of_a_frame(self):
        self.a.sendall(struct.pack("!I", 100) + b"only ten b")
        self.a.close()
        with self.assertRaises(ConnectionClosed):
            recv_frame(self.b)

    def test_close_in_the_middle_of_the_length_header(self):
        self.a.sendall(b"\x00\x00")
        self.a.close()
        with self.assertRaises(ConnectionClosed):
            recv_frame(self.b)

    def test_oversized_frame_is_refused_before_reading_it(self):
        self.a.sendall(struct.pack("!I", 1_000_000))
        with self.assertRaises(ProtocolError) as ctx:
            recv_frame(self.b, max_size=1000)
        self.assertNotIsInstance(ctx.exception, ConnectionClosed)
        # an absurd length must not make us try to allocate it
        self.a.sendall(struct.pack("!I", 0xFFFFFFFF))
        with self.assertRaises(ProtocolError):
            recv_frame(self.b)

    def test_recv_exact_zero_bytes(self):
        self.assertEqual(recv_exact(self.b, 0), b"")

    def test_sizes_around_the_single_send_threshold(self):
        # frames up to 64 KiB go out in one send; larger ones send the header separately
        for size in (65535, 65536, 65537, 65536 + 4):
            payload = bytes(range(251)) * (size // 251 + 1)
            payload = payload[:size]
            sender = threading.Thread(target=send_frame, args=(self.a, payload))
            sender.start()
            self.assertEqual(recv_frame(self.b), payload, size)
            sender.join()

    def test_a_huge_announced_frame_does_not_allocate_memory_up_front(self):
        # A peer announcing 30 MiB and then going silent must not make us allocate 30 MiB.
        self.a.sendall(struct.pack("!I", 30 * 1024 * 1024) + b"only a few bytes")
        self.a.close()
        tracemalloc.start()
        try:
            with self.assertRaises(ConnectionClosed):
                recv_frame(self.b)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 2 * 1024 * 1024, f"peak allocation {peak} bytes")


class MessageLimitTests(SocketPairCase):
    def test_the_header_size_limit_is_exact(self):
        filler = "x" * (MAX_HEADER_BYTES - len(b'{"type":"x","pad":""}'))
        ok = self.cipher.encrypt(b'{"type":"x","pad":"' + filler.encode() + b'"}\n')
        self.assertEqual(decode_message(self.cipher, ok)[0]["type"], "x")
        too_big = self.cipher.encrypt(b'{"type":"x","pad":"' + filler.encode() + b'y"}\n')
        with self.assertRaisesRegex(ProtocolError, "larger than"):
            decode_message(self.cipher, too_big)

    def test_a_large_body_does_not_count_against_the_header_limit(self):
        body = b"z" * (MAX_HEADER_BYTES * 20)
        message, received = decode_message(self.cipher, encode_message(self.cipher, {"type": "file", "size": len(body)}, body))
        self.assertEqual(len(received), len(body))

    def test_huge_integers_are_refused_quickly(self):
        # Converting a giant integer is quadratic on Python < 3.11 and would stall the server.
        started = time.monotonic()
        for digits in (21, 1000, 60_000):
            plaintext = b'{"type":"file","size":' + b"9" * digits + b"}\n"
            with self.assertRaises(ProtocolError, msg=str(digits)):
                decode_message(self.cipher, self.cipher.encrypt(plaintext))
        self.assertLess(time.monotonic() - started, 2.0)

    def test_ordinary_numbers_still_decode(self):
        for number in (0, -5, 25 * 1024 * 1024, 10 ** 19):
            plaintext = f'{{"type":"file","size":{number}}}\n'.encode()
            message, _ = decode_message(self.cipher, self.cipher.encrypt(plaintext))
            self.assertEqual(message["size"], number)

    def test_header_without_the_newline_separator_is_refused(self):
        with self.assertRaises(ProtocolError):
            decode_message(self.cipher, self.cipher.encrypt(b'{"type":"public","text":"x"}'))

    def test_recv_frame_limit_is_exact(self):
        send_frame(self.a, b"x" * 100)
        self.assertEqual(recv_frame(self.b, max_size=100), b"x" * 100)  # exactly at the limit: fine
        send_frame(self.a, b"x" * 101)
        with self.assertRaises(ProtocolError):
            recv_frame(self.b, max_size=100)


class KeepaliveTests(WatchdogTestCase):
    def test_enabling_keepalive_never_raises_and_turns_it_on(self):
        with socket.socket() as sock:
            enable_keepalive(sock)
            self.assertEqual(sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) != 0, True)
            interval = getattr(socket, "TCP_KEEPINTVL", None)
            if interval is not None and sys.platform != "win32":
                self.assertEqual(sock.getsockopt(socket.IPPROTO_TCP, interval), 10)

    def test_enabling_keepalive_on_a_closed_socket_is_harmless(self):
        sock = socket.socket()
        sock.close()
        enable_keepalive(sock)  # must not raise


class MessageTests(SocketPairCase):
    def test_message_round_trip_with_awkward_text(self):
        message = {"type": "public", "from": "a", "text": "line1\nline2 : , ^ | \"quoted\" ünï 🚀\r\n\x00"}
        send_message(self.a, self.cipher, message)
        received, body = recv_message(self.b, self.cipher)
        self.assertEqual(received, message)
        self.assertEqual(body, b"")

    def test_binary_body_may_contain_newlines_and_nulls(self):
        body = b"\n\n\x00\xff" + bytes(range(256)) + b"\n"
        send_message(self.a, self.cipher, {"type": "file", "name": "x.bin", "size": len(body)}, body)
        message, received_body = recv_message(self.b, self.cipher)
        self.assertEqual(message["name"], "x.bin")
        self.assertEqual(received_body, body)

    def test_nothing_readable_on_the_wire(self):
        send_message(self.a, self.cipher, {"type": "public", "text": "visible-secret-text"})
        self.b.settimeout(5)
        raw = recv_frame(self.b)
        self.assertNotIn(b"visible-secret-text", raw)
        self.assertNotIn(b"public", raw)

    def test_wrong_secret_raises_protocol_error(self):
        send_message(self.a, self.cipher, {"type": "x"})
        with self.assertRaises(ProtocolError):
            recv_message(self.b, Cipher("some-other-secret"))

    def test_malformed_plaintexts_are_rejected(self):
        bad_plaintexts = [
            b"",  # no separator
            b"no newline at all",
            b"{not json}\nbody",
            b"\xff\xfe\nbody",  # header not UTF-8
            b"[1,2,3]\n",  # JSON but not an object
            b'"just a string"\n',
            b'{"no_type": 1}\n',
            b'{"type": 5}\n',
            b'{"type": null}\n',
        ]
        for plaintext in bad_plaintexts:
            with self.assertRaises(ProtocolError, msg=repr(plaintext)):
                decode_message(self.cipher, self.cipher.encrypt(plaintext))

    def test_lone_surrogates_are_protocol_errors(self):
        for plaintext in (
            b'{"type": "x", "text": "\\ud800"}\n',  # cannot be re-encoded as UTF-8
            b'{"type": "\\udfff"}\n',
            b'{"type": "x", "text": ["ok", {"deeper": "\\udc00"}]}\n',
        ):
            with self.assertRaises(ProtocolError, msg=repr(plaintext[:40])):
                decode_message(self.cipher, self.cipher.encrypt(plaintext))

    def test_absurdly_nested_json_never_escapes_as_anything_but_a_protocol_error(self):
        # Older Pythons raise RecursionError for this, newer ones parse it; either is fine as
        # long as the only failure the caller ever sees is ProtocolError.
        for plaintext in (
            b'{"type": "x", "a": ' + b"[" * 200_000 + b"]" * 200_000 + b"}\n",
            b'{"type": "x", "a": ' + b'{"b": ' * 50_000 + b"1" + b"}" * 50_000 + b"}\n",
        ):
            try:
                message, _ = decode_message(self.cipher, self.cipher.encrypt(plaintext))
            except ProtocolError:
                continue
            self.assertEqual(message["type"], "x")

    def test_garbage_that_is_not_ciphertext_is_rejected(self):
        for garbage in (b"", b"short", b"x" * 100):
            with self.assertRaises(ProtocolError):
                decode_message(self.cipher, garbage)

    def test_header_is_single_line_json(self):
        payload = encode_message(self.cipher, {"type": "x", "text": "a\nb"})
        plaintext = self.cipher.decrypt(payload)
        header, _, body = plaintext.partition(b"\n")
        self.assertEqual(json.loads(header), {"type": "x", "text": "a\nb"})
        self.assertEqual(body, b"")


class ValidationTests(WatchdogTestCase):
    def test_usernames(self):
        for good in ("a", "taha", "Mr_X-2.0", "A" * MAX_USERNAME_LENGTH):
            self.assertIsNone(validate_username(good), good)
        for bad in ("", " ", "has space", "pipe|name", "new\nline", "emoji🚀", "a/b", "A" * (MAX_USERNAME_LENGTH + 1), None, 5, ["a"]):
            self.assertIsNotNone(validate_username(bad), repr(bad))

    def test_passwords(self):
        for good in ("x", "a long pass phrase with spaces!", "ü" * 36, "p" * MAX_PASSWORD_BYTES):
            self.assertIsNone(validate_password(good), good)
        for bad in ("", "p" * (MAX_PASSWORD_BYTES + 1), "ü" * 37, None, 12345, b"bytes"):
            self.assertIsNotNone(validate_password(bad), repr(bad))

    def test_text(self):
        for good in ("hi", "x" * MAX_TEXT_LENGTH, "  padded  ", "emoji 🚀 and ünï", "عربي / اردو", "family 👨\u200d👩\u200d👧"):
            self.assertIsNone(validate_text(good), repr(good))
        for bad in ("", "   ", "\n\t", "x" * (MAX_TEXT_LENGTH + 1), None, 5):
            self.assertIsNotNone(validate_text(bad), repr(bad))

    def test_text_with_control_characters_is_refused(self):
        # a line break would let one message pose as several, e.g. "[12:00] bob: i am bob"
        for char in ("\n", "\r", "\t", "\x00", "\x1b", "\x7f", "\x85", "\u2028", "\u2029", "\ud800"):
            self.assertIn("control characters", validate_text(f"hello{char}world") or "", repr(char))


class SanitizeFilenameTests(WatchdogTestCase):
    def test_table(self):
        cases = {
            "photo.jpg": "photo.jpg",
            "résumé.pdf": "résumé.pdf",
            "my file (1).txt": "my file (1).txt",
            "../../etc/passwd": "passwd",
            "/absolute/path/file.txt": "file.txt",
            "C:\\Windows\\System32\\evil.dll": "evil.dll",
            "..\\..\\win.ini": "win.ini",
            "a/b\\c/d.txt": "d.txt",
            "name\x00with\x1fcontrol.txt": "name_with_control.txt",
            'bad<>:"|?*chars.txt': "bad_______chars.txt",
            "  spaced.txt  ": "spaced.txt",
            "trailing.dot.": "trailing.dot",
            ".bashrc": "bashrc",
            "CON": "_CON",
            "nul.txt": "_nul.txt",
            "COM1.tar.gz": "_COM1.tar.gz",
            "LPT9": "_LPT9",
            "console.txt": "console.txt",
            "CONIN$": "_CONIN$",
            "conout$.log": "_conout$.log",
            "COM\u00b9": "_COM\u00b9",
            "lpt\u00b2.txt": "_lpt\u00b2.txt",
            "photo\u202egpj.exe": "photo_gpj.exe",  # right-to-left override can fake an extension
            "a\u200bb.txt": "a_b.txt",  # zero-width space
            "\ufeffnote.txt": "_note.txt",  # byte-order mark
            "x\u2066y\u2069.txt": "x_y_.txt",  # directional isolates
            "bad\ud800name.txt": "bad_name.txt",  # lone surrogate
            "line\u2028break.txt": "line_break.txt",
            "\u0686\u200c\u0627\u06cc.txt": "\u0686\u200c\u0627\u06cc.txt",  # Persian ZWNJ is legitimate
        }
        for raw, expected in cases.items():
            self.assertEqual(sanitize_filename(raw), expected, repr(raw))

    def test_unusable_names_fall_back_to_default(self):
        for raw in ("", ".", "..", "...", "/", "\\", " ", "../..", "./", None, 5, b"x", ["a"]):
            self.assertEqual(sanitize_filename(raw), "file", repr(raw))
        self.assertEqual(sanitize_filename("", default="unnamed"), "unnamed")

    def test_long_names_are_shortened_but_keep_their_extension(self):
        name = sanitize_filename("a" * 500 + ".txt")
        self.assertLessEqual(len(name), MAX_FILENAME_LENGTH)
        self.assertTrue(name.endswith(".txt"))
        weird = sanitize_filename("b" * 20 + "." + "e" * 500)
        self.assertLessEqual(len(weird), MAX_FILENAME_LENGTH)
        self.assertNotIn("/", weird)

    def test_every_invisible_or_reordering_character_is_replaced(self):
        invisible = "\u00ad\u061c\u200b\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2060\u2066\u2067\u2068\u2069\ufeff"
        for char in invisible:
            self.assertEqual(sanitize_filename(f"a{char}b.txt"), "a_b.txt", hex(ord(char)))

    def test_names_that_are_short_in_characters_but_long_in_bytes_fit_a_file_system(self):
        # Linux allows 255 bytes per name; Urdu/Persian letters take two bytes, CJK three.
        for letters in ("\u0627\u0631\u062f\u0648", "\u4e2d\u6587", "\u00e9", "\U0001f680"):
            name = sanitize_filename(letters * 200 + ".txt")
            self.assertLessEqual(len(name), MAX_FILENAME_LENGTH)
            self.assertLessEqual(len(name.encode("utf-8")), MAX_FILENAME_BYTES)
            self.assertTrue(name.endswith(".txt"), name[-8:])

    def test_sanitising_twice_changes_nothing(self):
        import random
        rng = random.Random(1535)
        alphabet = list("ab.. /\\:<>|?*_-") + ["\u202e", "\u200b", "\ud800", "\x00", "\u0627", "\u4e2d", "\U0001f680", "CON", "com1", "nul"]
        for _ in range(4000):
            raw = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 130)))
            once = sanitize_filename(raw)
            self.assertEqual(sanitize_filename(once), once, repr(raw))
            self.assertLessEqual(len(once), MAX_FILENAME_LENGTH)
            self.assertLessEqual(len(once.encode("utf-8")), MAX_FILENAME_BYTES)
            self.assertNotIn(once.split(".")[0].strip().lower(), ("con", "prn", "aux", "nul", "com1", "lpt1"), repr(raw))

    def test_com9_and_lpt9_are_reserved_too(self):
        for name in ("COM9", "lpt9.txt", "Com5.tar.gz"):
            self.assertTrue(sanitize_filename(name).startswith("_"), name)

    def test_the_length_limit_holds_even_after_a_reserved_name_prefix(self):
        for raw in ("con." + "a" * 200, "CON" + "." * 3 + "b" * 98, "nul" + ".x" * 80, "COM1." + "z" * 100):
            result = sanitize_filename(raw)
            self.assertLessEqual(len(result), MAX_FILENAME_LENGTH, raw[:20])
            self.assertTrue(result.startswith("_"), result[:20])

    def test_result_is_always_a_single_safe_component(self):
        nasty = [
            "../" * 50 + "x", "..\\" * 50 + "x", "a/../../b", "....//....//x", "%2e%2e/x",
            "x" * 1000, "\u202etxt.exe", "a\nb", "~/.ssh/authorized_keys", "$HOME/x",
            "\ud800", "con." + "a" * 150, "\u200b\u200b", "a" * 98 + ".\u202egpj",
        ]
        for raw in nasty:
            result = sanitize_filename(raw)
            self.assertTrue(result)
            self.assertNotIn("/", result)
            self.assertNotIn("\\", result)
            self.assertNotIn("\x00", result)
            self.assertNotIn(result, (".", ".."))
            self.assertLessEqual(len(result), MAX_FILENAME_LENGTH)
            self.assertFalse(
                [c for c in result if unicodedata.category(c) in ("Cc", "Cs", "Zl", "Zp") or c in "\u202e\u200b"],
                repr(result),
            )


if __name__ == "__main__":
    unittest.main()
