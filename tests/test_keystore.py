import os
import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from courier.errors import (
    InsecurePermissionsError,
    KeyLoadError,
    KeyStoreError,
    WrongPassphraseError,
)
from courier.storage.keystore import load_private_key, save_private_key


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_save_and_load_round_trip(tmp_path, rsa_key, passphrase):
    path = tmp_path / "keys" / "sign.key"
    save_private_key(path, rsa_key, passphrase)
    loaded = load_private_key(path, passphrase)
    assert loaded.private_numbers() == rsa_key.private_numbers()


def test_file_and_dir_permissions(tmp_path, rsa_key, passphrase):
    path = tmp_path / "keys" / "sign.key"
    save_private_key(path, rsa_key, passphrase)
    assert _mode(path) == 0o600
    assert _mode(path.parent) == 0o700


def test_file_is_encrypted_pkcs8(tmp_path, rsa_key, passphrase):
    path = tmp_path / "keys" / "sign.key"
    save_private_key(path, rsa_key, passphrase)
    data = path.read_bytes()
    assert data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")


def test_wrong_passphrase_rejected(tmp_path, rsa_key, passphrase):
    path = tmp_path / "keys" / "sign.key"
    save_private_key(path, rsa_key, passphrase)
    with pytest.raises(WrongPassphraseError):
        load_private_key(path, b"not the passphrase")


def test_loose_file_permissions_rejected(tmp_path, rsa_key, passphrase):
    path = tmp_path / "keys" / "sign.key"
    save_private_key(path, rsa_key, passphrase)
    os.chmod(path, 0o644)
    with pytest.raises(InsecurePermissionsError):
        load_private_key(path, passphrase)


def test_loose_directory_permissions_rejected(tmp_path, rsa_key, passphrase):
    path = tmp_path / "keys" / "sign.key"
    save_private_key(path, rsa_key, passphrase)
    os.chmod(path.parent, 0o755)
    with pytest.raises(InsecurePermissionsError):
        load_private_key(path, passphrase)


def test_symlinked_key_rejected(tmp_path, rsa_key, passphrase):
    real = tmp_path / "keys" / "real.key"
    save_private_key(real, rsa_key, passphrase)
    link = tmp_path / "keys" / "link.key"
    link.symlink_to(real)
    with pytest.raises(InsecurePermissionsError):
        load_private_key(link, passphrase)


def test_unencrypted_key_rejected(tmp_path, rsa_key):
    keys = tmp_path / "keys"
    keys.mkdir(mode=0o700)
    path = keys / "plain.key"
    path.write_bytes(rsa_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    os.chmod(path, 0o600)
    with pytest.raises(KeyLoadError):
        load_private_key(path, b"anything-long")


def test_refuses_overwrite(tmp_path, rsa_key, passphrase):
    path = tmp_path / "keys" / "sign.key"
    save_private_key(path, rsa_key, passphrase)
    with pytest.raises(KeyStoreError):
        save_private_key(path, rsa_key, passphrase)
    save_private_key(path, rsa_key, passphrase, overwrite=True)  # explicit overwrite is allowed


def test_short_passphrase_rejected(tmp_path, rsa_key):
    with pytest.raises(KeyStoreError):
        save_private_key(tmp_path / "keys" / "k.key", rsa_key, b"short")


def test_wrong_key_size_rejected(tmp_path, passphrase):
    small = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(KeyLoadError):
        save_private_key(tmp_path / "keys" / "k.key", small, passphrase)


def test_non_rsa_key_rejected_on_load(tmp_path, passphrase):
    keys = tmp_path / "keys"
    keys.mkdir(mode=0o700)
    path = keys / "ec.key"
    path.write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase),
    ))
    os.chmod(path, 0o600)
    with pytest.raises(KeyLoadError):
        load_private_key(path, passphrase)


def test_missing_file(tmp_path, passphrase):
    with pytest.raises(KeyLoadError):
        load_private_key(tmp_path / "nope.key", passphrase)
