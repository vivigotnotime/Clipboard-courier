"""Encrypted private-key storage (design notes, section 9).

Keys are stored as passphrase-encrypted PKCS#8 PEM files with mode 0600 in a
directory with mode 0700. Loading refuses files that other users could read,
files that are not encrypted, and keys that are not RSA-3072.

To see which KDF and cipher the installed cryptography version used, run:
    openssl asn1parse -in <file>.key
and look for the PBES2 / PBKDF2 / cipher object names near the top.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from courier.errors import (
    InsecurePermissionsError,
    KeyLoadError,
    KeyStoreError,
    WrongPassphraseError,
)

RSA_KEY_SIZE = 3072
RSA_PUBLIC_EXPONENT = 65537
MIN_PASSPHRASE_LENGTH = 8


def generate_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE)


def ensure_private_dir(path: Path) -> None:
    """Create a directory (and parents) owned by us with mode 0700, or verify an existing one."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)  # mkdir's mode is filtered by umask; set it explicitly
    _check_private(path, max_mode=0o700)


def save_private_key(
    path: Path,
    key: rsa.RSAPrivateKey,
    passphrase: bytes,
    *,
    overwrite: bool = False,
) -> None:
    """Encrypt `key` with `passphrase` and write it to `path` with mode 0600.

    The file is written to a temporary name and then renamed, so a crash
    never leaves a half-written key behind.
    """
    _check_passphrase(passphrase)
    _check_rsa_key(key)
    path = Path(path)
    if path.exists() and not overwrite:
        raise KeyStoreError(f"refusing to overwrite existing key file {path}")
    ensure_private_dir(path.parent)

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )

    tmp = path.with_name(path.name + ".tmp")
    # O_EXCL: fail rather than follow a pre-existing file or symlink at tmp.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def load_private_key(path: Path, passphrase: bytes) -> rsa.RSAPrivateKey:
    """Load and decrypt an RSA-3072 private key, enforcing file permissions."""
    path = Path(path)
    if not path.is_file():
        raise KeyLoadError(f"key file not found: {path}")
    _check_private(path.parent, max_mode=0o700)
    _check_private(path, max_mode=0o600)

    data = path.read_bytes()
    if b"-----BEGIN ENCRYPTED PRIVATE KEY-----" not in data:
        raise KeyLoadError(f"{path} is not an encrypted PKCS#8 key; refusing to use it")

    try:
        key = serialization.load_pem_private_key(data, password=passphrase)
    except ValueError:
        # cryptography raises ValueError for a wrong passphrase and for corrupt data;
        # it does not let us tell those apart reliably.
        raise WrongPassphraseError(f"could not decrypt {path}: wrong passphrase or corrupt file") from None
    except TypeError as exc:
        raise KeyLoadError(f"could not load {path}: {exc}") from None

    _check_rsa_key(key)
    return key


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
    """Reject paths not owned by us, or with any permission bits beyond max_mode."""
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
