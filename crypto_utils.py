"""Authenticated encryption helpers shared by the Synapse server and client.

Every frame on the wire is encrypted with AES-256-GCM using a key derived from
a shared secret (``SYNAPSE_SECRET``).  GCM provides both confidentiality and
integrity: a frame that was modified in transit, or encrypted with a different
secret, fails to decrypt instead of producing garbage.

The shared secret is **never** stored in the source code.  It is read from the
``SYNAPSE_SECRET`` environment variable or, if that is unset, from a ``.env``
file that sits next to this module (see ``.env.example``).
"""

from __future__ import annotations

import base64
import functools
import hashlib
import os
import re
from pathlib import Path
from typing import Dict, Optional

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

SECRET_ENV_VAR = "SYNAPSE_SECRET"
DEFAULT_ENV_FILE = Path(__file__).resolve().parent / ".env"

MIN_SECRET_LENGTH = 8
NONCE_SIZE = 12  # bytes; the recommended nonce size for GCM
TAG_SIZE = 16  # bytes; full-length GCM authentication tag
KEY_SIZE = 32  # bytes; AES-256

_KDF_SALT = b"synapse-chat-v1"
_KDF_ITERATIONS = 200_000


class CryptoError(Exception):
    """Base class for all errors raised by this module."""


class MissingSecretError(CryptoError):
    """The shared secret is not configured, or is too short to be safe."""


class DecryptionError(CryptoError):
    """A message could not be decrypted (wrong secret or corrupted/tampered data)."""


@functools.lru_cache(maxsize=16)
def _derive_key(secret: str) -> bytes:
    """Stretch the shared secret into a 256-bit AES key (PBKDF2-HMAC-SHA256)."""
    return hashlib.pbkdf2_hmac(
        "sha256", secret.encode("utf-8"), _KDF_SALT, _KDF_ITERATIONS, dklen=KEY_SIZE
    )


def read_env_file(path: Path) -> Dict[str, str]:
    """Parse a minimal ``KEY=VALUE`` file.  Missing or unreadable files yield ``{}``."""
    values: Dict[str, str] = {}
    try:
        raw = Path(path).read_bytes()
        # Windows PowerShell's ``>`` writes UTF-16 (with a BOM); editors may add a UTF-8 BOM.
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = raw.decode("utf-16", errors="replace")
        else:
            # "replace": a stray non-UTF-8 byte (say in a comment) must not hide the whole file
            text = raw.decode("utf-8-sig", errors="replace")
    except OSError:
        return values
    # Split on real line endings only: str.splitlines() would also cut at exotic separators.
    for raw_line in re.split(r"\r\n|\r|\n", text):
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def get_setting(name: str, env_file: Optional[Path] = None) -> Optional[str]:
    """Look up a setting: the environment variable wins, then the ``.env`` file."""
    value = os.environ.get(name)
    if value:
        return value
    return read_env_file(env_file or DEFAULT_ENV_FILE).get(name) or None


class Cipher:
    """Encrypts and decrypts bytes (or text) with a key derived from a shared secret."""

    def __init__(self, secret: str):
        if not isinstance(secret, str) or len(secret) < MIN_SECRET_LENGTH:
            raise MissingSecretError(
                f"The shared secret must be at least {MIN_SECRET_LENGTH} characters long."
            )
        self._key = _derive_key(secret)

    @classmethod
    def from_environment(cls, env_file: Optional[Path] = None) -> "Cipher":
        """Build a cipher from ``SYNAPSE_SECRET`` (environment first, then ``.env``)."""
        secret = get_setting(SECRET_ENV_VAR, env_file)
        if not secret:
            raise MissingSecretError(
                f"{SECRET_ENV_VAR} is not set. Choose a shared secret (the server and "
                f"every client must use the same one) and either export it as an "
                f"environment variable or put it in a .env file. "
                f"See .env.example for details."
            )
        return cls(secret)

    def encrypt(self, data: bytes) -> bytes:
        """Return ``nonce || tag || ciphertext`` for ``data``."""
        nonce = get_random_bytes(NONCE_SIZE)
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return nonce + tag + ciphertext

    def decrypt(self, blob: bytes) -> bytes:
        """Inverse of :meth:`encrypt`.  Raises :class:`DecryptionError` on any failure."""
        if len(blob) < NONCE_SIZE + TAG_SIZE:
            raise DecryptionError("Encrypted message is too short.")
        nonce = blob[:NONCE_SIZE]
        tag = blob[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
        ciphertext = blob[NONCE_SIZE + TAG_SIZE:]
        try:
            cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as exc:
            raise DecryptionError(
                "Could not decrypt message: wrong shared secret or corrupted data."
            ) from exc

    def encrypt_text(self, text: str) -> str:
        """Encrypt ``text`` and return it base64-encoded (safe to store in JSON)."""
        return base64.b64encode(self.encrypt(text.encode("utf-8"))).decode("ascii")

    def decrypt_text(self, token: str) -> str:
        """Inverse of :meth:`encrypt_text`."""
        try:
            blob = base64.b64decode(token.encode("ascii"), validate=True)
            plaintext = self.decrypt(blob)  # raises DecryptionError on failure
            return plaintext.decode("utf-8")
        except ValueError as exc:  # bad base64 / non-ASCII token / non-UTF-8 plaintext
            raise DecryptionError("Encrypted text is not valid.") from exc
