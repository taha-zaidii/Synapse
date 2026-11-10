import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from crypto_utils import (
    NONCE_SIZE,
    SECRET_ENV_VAR,
    TAG_SIZE,
    Cipher,
    DecryptionError,
    MissingSecretError,
    get_setting,
    read_env_file,
)
from tests.watchdog import WatchdogTestCase


class CipherTests(WatchdogTestCase):
    def setUp(self):
        self.cipher = Cipher("a-reasonable-shared-secret")

    def test_round_trip_bytes(self):
        for data in (b"", b"x", b"hello world", os.urandom(100_000)):
            self.assertEqual(self.cipher.decrypt(self.cipher.encrypt(data)), data)

    def test_round_trip_text_including_unicode(self):
        for text in ("", "plain", "naïve café ☕ 你好 🚀", "line\nbreaks : , ^ | and quotes \" '"):
            self.assertEqual(self.cipher.decrypt_text(self.cipher.encrypt_text(text)), text)

    def test_ciphertext_does_not_contain_plaintext_and_is_randomised(self):
        first = self.cipher.encrypt(b"top secret message")
        second = self.cipher.encrypt(b"top secret message")
        self.assertNotIn(b"top secret", first)
        self.assertNotEqual(first, second)  # fresh nonce every time
        self.assertEqual(len(first), NONCE_SIZE + TAG_SIZE + len(b"top secret message"))

    def test_secrets_that_differ_only_at_the_end_do_not_interoperate(self):
        first, second = Cipher("same-prefix-secret-A"), Cipher("same-prefix-secret-B")
        with self.assertRaises(DecryptionError):
            second.decrypt(first.encrypt(b"hello"))

    def test_text_tokens_with_stray_characters_are_refused(self):
        token = self.cipher.encrypt_text("hello")
        for broken in (token[:8] + "\n" + token[8:], " " + token, token + "!", token[:-2]):
            with self.assertRaises(DecryptionError, msg=repr(broken)):
                self.cipher.decrypt_text(broken)

    def test_wrong_secret_is_rejected(self):
        blob = self.cipher.encrypt(b"data")
        with self.assertRaises(DecryptionError):
            Cipher("a-different-shared-secret").decrypt(blob)

    def test_any_single_bit_flip_is_detected(self):
        blob = self.cipher.encrypt(b"integrity matters")
        for index in range(len(blob)):
            tampered = bytearray(blob)
            tampered[index] ^= 0x01
            with self.assertRaises(DecryptionError, msg=f"byte {index}"):
                self.cipher.decrypt(bytes(tampered))

    def test_truncated_and_empty_input_is_rejected(self):
        blob = self.cipher.encrypt(b"data")
        for bad in (b"", blob[:5], blob[: NONCE_SIZE + TAG_SIZE - 1], blob[:-1]):
            with self.assertRaises(DecryptionError):
                self.cipher.decrypt(bad)

    def test_invalid_text_tokens_are_rejected(self):
        for token in ("not base64!!", "", "AAAA", "é"):
            with self.assertRaises(DecryptionError):
                self.cipher.decrypt_text(token)

    def test_short_secret_is_refused(self):
        for secret in ("", "short", "1234567"):
            with self.assertRaises(MissingSecretError):
                Cipher(secret)
        Cipher("12345678")  # the minimum length is allowed


class SecretLoadingTests(WatchdogTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env_file = Path(self.tmp.name) / ".env"
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop(SECRET_ENV_VAR, None)

    def test_missing_secret_gives_helpful_error(self):
        with self.assertRaises(MissingSecretError) as ctx:
            Cipher.from_environment(env_file=self.env_file)
        self.assertIn(SECRET_ENV_VAR, str(ctx.exception))
        self.assertIn(".env.example", str(ctx.exception))

    def test_secret_from_environment_variable(self):
        os.environ[SECRET_ENV_VAR] = "secret-from-the-environment"
        cipher = Cipher.from_environment(env_file=self.env_file)
        self.assertEqual(cipher.decrypt(Cipher("secret-from-the-environment").encrypt(b"x")), b"x")

    def test_secret_from_env_file(self):
        self.env_file.write_text(f'# comment\nOTHER=1\n{SECRET_ENV_VAR}="secret-from-the-file"\n')
        cipher = Cipher.from_environment(env_file=self.env_file)
        self.assertEqual(cipher.decrypt(Cipher("secret-from-the-file").encrypt(b"x")), b"x")

    def test_environment_wins_over_env_file(self):
        self.env_file.write_text(f"{SECRET_ENV_VAR}=secret-from-the-file\n")
        os.environ[SECRET_ENV_VAR] = "secret-from-the-environment"
        cipher = Cipher.from_environment(env_file=self.env_file)
        self.assertEqual(cipher.decrypt(Cipher("secret-from-the-environment").encrypt(b"x")), b"x")

    def test_too_short_secret_from_environment_is_refused(self):
        os.environ[SECRET_ENV_VAR] = "tiny"
        with self.assertRaises(MissingSecretError):
            Cipher.from_environment(env_file=self.env_file)

    def test_default_env_file_is_used_when_none_given(self):
        self.env_file.write_text(f"{SECRET_ENV_VAR}=secret-from-default-file\n")
        with mock.patch("crypto_utils.DEFAULT_ENV_FILE", self.env_file):
            cipher = Cipher.from_environment()
        self.assertEqual(cipher.decrypt(Cipher("secret-from-default-file").encrypt(b"x")), b"x")


class GetSettingTests(WatchdogTestCase):
    def test_environment_wins_then_file_then_none(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ):
            env_file = Path(tmp) / ".env"
            env_file.write_text("SYNAPSE_TEST_SETTING=from-file\nOTHER=1\n")
            os.environ.pop("SYNAPSE_TEST_SETTING", None)
            self.assertEqual(get_setting("SYNAPSE_TEST_SETTING", env_file), "from-file")
            os.environ["SYNAPSE_TEST_SETTING"] = "from-environment"
            self.assertEqual(get_setting("SYNAPSE_TEST_SETTING", env_file), "from-environment")
            self.assertIsNone(get_setting("SYNAPSE_NOT_SET_ANYWHERE", env_file))
            env_file.write_text("SYNAPSE_EMPTY=\n")
            self.assertIsNone(get_setting("SYNAPSE_EMPTY", env_file))

    def test_default_env_file_is_consulted(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ):
            os.environ.pop("SYNAPSE_TEST_SETTING", None)
            env_file = Path(tmp) / ".env"
            env_file.write_text("SYNAPSE_TEST_SETTING=default-file\n")
            with mock.patch("crypto_utils.DEFAULT_ENV_FILE", env_file):
                self.assertEqual(get_setting("SYNAPSE_TEST_SETTING"), "default-file")


class ReadEnvFileTests(WatchdogTestCase):
    def test_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text(
                "\n# a comment\n"
                "PLAIN=value\n"
                "  SPACED  =  padded value  \n"
                'DOUBLE="quoted value"\n'
                "SINGLE='single quoted'\n"
                "export EXPORTED=yes\n"
                "EQUALS=a=b=c\n"
                "no_equals_sign\n"
                "=novalue_key\n"
                "EMPTY=\n"
            )
            self.assertEqual(
                read_env_file(path),
                {
                    "PLAIN": "value",
                    "SPACED": "padded value",
                    "DOUBLE": "quoted value",
                    "SINGLE": "single quoted",
                    "EXPORTED": "yes",
                    "EQUALS": "a=b=c",
                    "EMPTY": "",
                },
            )

    def test_files_with_a_byte_order_mark_are_understood(self):
        # PowerShell's ">" produces UTF-16 with a BOM; some editors add a UTF-8 BOM.
        content = "SYNAPSE_SECRET=from-a-bom-file\r\nOTHER=1\r\n"
        expected = {"SYNAPSE_SECRET": "from-a-bom-file", "OTHER": "1"}
        with tempfile.TemporaryDirectory() as tmp:
            for name, data in (
                ("utf16", content.encode("utf-16")),  # includes the BOM
                ("utf16be", b"\xfe\xff" + content.encode("utf-16-be")),
                ("utf8bom", b"\xef\xbb\xbf" + content.encode("utf-8")),
                ("utf8", content.encode("utf-8")),
            ):
                path = Path(tmp) / name
                path.write_bytes(data)
                self.assertEqual(read_env_file(path), expected, name)

    def test_a_stray_non_utf8_byte_does_not_hide_the_whole_file(self):
        # e.g. a comment saved in a legacy encoding must not make "SYNAPSE_SECRET is not set"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_bytes(b"# caf\xe9 notes\nSYNAPSE_SECRET=still-found\n")
            self.assertEqual(read_env_file(path)["SYNAPSE_SECRET"], "still-found")

    def test_only_real_line_endings_split_the_file(self):
        # str.splitlines() would also cut at \x0b, \x1c, \x85, U+2028 ... inside a value
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            secret = "left\u2028right\x0bmore\x85end"
            path.write_bytes(f"SYNAPSE_SECRET={secret}\nOTHER=1\r\nLAST=2\r".encode("utf-8"))
            values = read_env_file(path)
            self.assertEqual(values, {"SYNAPSE_SECRET": secret, "OTHER": "1", "LAST": "2"})

    def test_missing_file_yields_empty_dict(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(read_env_file(Path(tmp) / "nope"), {})
            self.assertEqual(read_env_file(Path(tmp)), {})  # a directory is not a file


if __name__ == "__main__":
    unittest.main()
