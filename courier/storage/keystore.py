"""Encrypted private-key storage (design notes, section 9).

Key file format
---------------
A key file is PEM-style text:

    -----BEGIN COURIER ENCRYPTED KEY-----
    <base64 of: header || ciphertext>
    -----END COURIER ENCRYPTED KEY-----

The binary header has a fixed layout, so it can be parsed strictly:

    magic     5 bytes   b"CCKEY"
    version   1 byte    1
    label_len 1 byte    length of label (1..32)
    label     n bytes   ASCII, what the key is for: "tls", "sign", "enc", "relay-tls", "ca"
    log2_n    1 byte    scrypt cost parameter N = 2**log2_n
    r         1 byte    scrypt block size (must be 8)
    p         1 byte    scrypt parallelism (must be 1)
    salt     16 bytes   random, fresh for every save
    nonce    12 bytes   random, fresh for every save

    ciphertext = AES-256-GCM(key, nonce, PKCS#8 DER of the private key, aad=header)
    key        = scrypt(passphrase, salt, N, r, p, length=32)

Why this design:
- scrypt is memory-hard: every passphrase guess costs 2**17 * 128 * 8 bytes
  (128 MiB) of memory and about a third of a second, which makes guessing a
  stolen file's passphrase expensive, especially on GPUs.
- AES-GCM authenticates as well as encrypts: a wrong passphrase or any change
  to the file is detected, instead of yielding garbage.
- The whole header is the GCM associated data, so the label, the scrypt
  parameters, the salt and the nonce cannot be changed without detection.
  Binding the label stops a file being swapped for another key's file, such as
  enc.key copied over sign.key.

File handling: the file is mode 0600 inside a 0700 directory, written atomically.
Loading refuses symlinks, files or directories other users can access, files
not owned by us, and keys that are not RSA-3072.
"""
from __future__ import annotations

import base64
import os
import re
import stat
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from courier.errors import (
    InsecurePermissionsError,
    KeyLoadError,
    KeyStoreError,
    WrongPassphraseError,
)
from courier.storage.files import atomic_write

RSA_KEY_SIZE = 3072
RSA_PUBLIC_EXPONENT = 65537
MIN_PASSPHRASE_LENGTH = 8

MAGIC = b"CCKEY"
FORMAT_VERSION = 1
PEM_BEGIN = b"-----BEGIN COURIER ENCRYPTED KEY-----"
PEM_END = b"-----END COURIER ENCRYPTED KEY-----"

PRODUCTION_SCRYPT_LOG2N = 17          # N = 131072 -> 128 MiB, ~0.35 s per attempt
DEFAULT_SCRYPT_LOG2N = PRODUCTION_SCRYPT_LOG2N   # tests lower this for speed
MIN_SCRYPT_LOG2N = 14                 # refuse files weaker than this
MAX_SCRYPT_LOG2N = 20                 # refuse files that would need > 1 GiB to open
SCRYPT_R = 8
SCRYPT_P = 1
SALT_LEN = 16
NONCE_LEN = 12
MAX_FILE_SIZE = 64 * 1024             # an RSA-3072 key file is ~2.6 KB

_LABEL_RE = re.compile(rb"^[a-z0-9-]{1,32}$")


def generate_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE)


def ensure_private_dir(path: Path) -> None:
    """Create a directory (and parents) with mode 0700, or verify an existing one."""
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)  # mkdir's mode is filtered by umask; set it explicitly
    _check_private(path, max_mode=0o700)


def save_private_key(
    path: Path,
    key: rsa.RSAPrivateKey,
    passphrase: bytes,
    *,
    label: str,
    overwrite: bool = False,
    scrypt_log2n: int | None = None,
) -> None:
    """Encrypt `key` under `passphrase` and write it to `path` (mode 0600)."""
    _check_passphrase(passphrase)
    _check_rsa_key(key)
    label_bytes = _check_label(label)
    log2n = DEFAULT_SCRYPT_LOG2N if scrypt_log2n is None else scrypt_log2n
    if not MIN_SCRYPT_LOG2N <= log2n <= MAX_SCRYPT_LOG2N:
        raise KeyStoreError(f"scrypt cost 2**{log2n} outside allowed range")

    path = Path(path)
    if path.exists() and not overwrite:
        raise KeyStoreError(f"refusing to overwrite existing key file {path}")
    ensure_private_dir(path.parent)

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    header = (
        MAGIC
        + struct.pack(">BB", FORMAT_VERSION, len(label_bytes))
        + label_bytes
        + struct.pack(">BBB", log2n, SCRYPT_R, SCRYPT_P)
        + salt
        + nonce
    )
    plaintext = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    wrapping_key = _derive(passphrase, salt, log2n)
    ciphertext = AESGCM(wrapping_key).encrypt(nonce, plaintext, header)

    atomic_write(path, _armor(header + ciphertext), mode=0o600, overwrite=overwrite)


def load_private_key(path: Path, passphrase: bytes, *, label: str) -> rsa.RSAPrivateKey:
    """Decrypt and return the RSA-3072 key stored at `path`.

    `label` is what the caller expects this key to be for; a file holding a
    key for anything else is refused.
    """
    path = Path(path)
    expected_label = _check_label(label)
    if not path.is_file():
        raise KeyLoadError(f"key file not found: {path}")
    _check_private(path.parent, max_mode=0o700)
    _check_private(path, max_mode=0o600)
    if path.stat().st_size > MAX_FILE_SIZE:
        raise KeyLoadError(f"{path} is too large to be a Courier key file")

    blob = _dearmor(path.read_bytes(), path)
    header, ciphertext, file_label, log2n, salt, nonce = _parse(blob, path)

    if file_label != expected_label:
        raise KeyLoadError(
            f"{path} holds a {file_label.decode()!r} key, expected {expected_label.decode()!r}"
        )

    wrapping_key = _derive(passphrase, salt, log2n)
    try:
        plaintext = AESGCM(wrapping_key).decrypt(nonce, ciphertext, header)
    except InvalidTag:
        # GCM cannot tell a wrong passphrase from a modified file: both fail the tag.
        raise WrongPassphraseError(
            f"could not decrypt {path}: wrong passphrase, or the file has been modified"
        ) from None

    try:
        key = serialization.load_der_private_key(plaintext, password=None)
    except (ValueError, TypeError):
        raise KeyLoadError(f"{path} decrypted but does not contain a valid private key") from None
    _check_rsa_key(key)
    return key


# --- helpers -----------------------------------------------------------------

def _derive(passphrase: bytes, salt: bytes, log2n: int) -> bytes:
    _check_passphrase(passphrase)
    kdf = Scrypt(salt=salt, length=32, n=2 ** log2n, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase)


def _armor(blob: bytes) -> bytes:
    b64 = base64.b64encode(blob)
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return PEM_BEGIN + b"\n" + b"\n".join(lines) + b"\n" + PEM_END + b"\n"


def _dearmor(data: bytes, path: Path) -> bytes:
    lines = data.strip().split(b"\n")
    if len(lines) < 3 or lines[0] != PEM_BEGIN or lines[-1] != PEM_END:
        raise KeyLoadError(f"{path} is not a Courier encrypted key file")
    try:
        return base64.b64decode(b"".join(lines[1:-1]), validate=True)
    except ValueError:
        raise KeyLoadError(f"{path} has corrupt base64 content") from None


def _parse(blob: bytes, path: Path):
    """Strictly parse header || ciphertext. Returns the pieces or raises KeyLoadError."""
    def bad(reason: str) -> KeyLoadError:
        return KeyLoadError(f"{path} is malformed: {reason}")

    if len(blob) < len(MAGIC) + 2 or blob[:len(MAGIC)] != MAGIC:
        raise bad("wrong magic bytes")
    pos = len(MAGIC)
    version, label_len = struct.unpack_from(">BB", blob, pos)
    pos += 2
    if version != FORMAT_VERSION:
        raise bad(f"unsupported format version {version}")
    if not 1 <= label_len <= 32:
        raise bad("bad label length")

    fixed_tail = 3 + SALT_LEN + NONCE_LEN
    if len(blob) < pos + label_len + fixed_tail + 16:   # 16 = GCM tag
        raise bad("truncated")
    label = blob[pos:pos + label_len]
    pos += label_len
    if not _LABEL_RE.fullmatch(label):
        raise bad("bad label")

    log2n, r, p = struct.unpack_from(">BBB", blob, pos)
    pos += 3
    if not MIN_SCRYPT_LOG2N <= log2n <= MAX_SCRYPT_LOG2N:
        raise bad(f"scrypt cost 2**{log2n} outside allowed range")
    if r != SCRYPT_R or p != SCRYPT_P:
        raise bad("unsupported scrypt parameters")

    salt = blob[pos:pos + SALT_LEN]
    pos += SALT_LEN
    nonce = blob[pos:pos + NONCE_LEN]
    pos += NONCE_LEN
    return blob[:pos], blob[pos:], label, log2n, salt, nonce


def _check_label(label: str) -> bytes:
    if not isinstance(label, str):
        raise KeyStoreError("label must be a string")
    raw = label.encode("ascii", errors="replace")
    if not _LABEL_RE.fullmatch(raw):
        raise KeyStoreError(f"invalid key label {label!r}")
    return raw


def _check_passphrase(passphrase: bytes) -> None:
    if not isinstance(passphrase, bytes):
        raise KeyStoreError("passphrase must be bytes")
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise KeyStoreError(f"passphrase must be at least {MIN_PASSPHRASE_LENGTH} bytes")


def _check_rsa_key(key: object) -> None:
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyLoadError("key is not an RSA private key")
    if key.key_size != RSA_KEY_SIZE:
        raise KeyLoadError(f"key is RSA-{key.key_size}, expected RSA-{RSA_KEY_SIZE}")


def _check_private(path: Path, *, max_mode: int) -> None:
    """Reject paths that are symlinks, not owned by us, or with bits beyond max_mode."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise InsecurePermissionsError(f"{path} is a symbolic link")
    if st.st_uid != os.geteuid():
        raise InsecurePermissionsError(f"{path} is not owned by the current user")
    mode = stat.S_IMODE(st.st_mode)
    if mode & ~max_mode:
        raise InsecurePermissionsError(
            f"{path} has permissions {mode:04o}; must be {max_mode:04o} or stricter"
        )
