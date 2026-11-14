import base64
import os
import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from courier.errors import (
    InsecurePermissionsError,
    KeyLoadError,
    KeyStoreError,
    WrongPassphraseError,
)
from courier.storage import keystore
from courier.storage.keystore import load_private_key, save_private_key


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def _save(tmp_path, key, passphrase, name="sign.key", label="sign", **kw):
    path = tmp_path / "keys" / name
    save_private_key(path, key, passphrase, label=label, **kw)
    return path


def _blob(path):
    """The binary header || ciphertext inside a key file."""
    lines = path.read_bytes().strip().split(b"\n")
    return bytearray(base64.b64decode(b"".join(lines[1:-1])))


def _write_blob(path, blob):
    os.chmod(path, 0o600)
    path.write_bytes(keystore._armor(bytes(blob)))


# --- normal operation ----------------------------------------------------------

def test_save_and_load_round_trip(tmp_path, rsa_key, passphrase):
    path = _save(tmp_path, rsa_key, passphrase)
    loaded = load_private_key(path, passphrase, label="sign")
    assert loaded.private_numbers() == rsa_key.private_numbers()


def test_file_and_dir_permissions(tmp_path, rsa_key, passphrase):
    path = _save(tmp_path, rsa_key, passphrase)
    assert _mode(path) == 0o600
    assert _mode(path.parent) == 0o700


def test_file_format(tmp_path, rsa_key, passphrase):
    path = _save(tmp_path, rsa_key, passphrase)
    assert path.read_bytes().startswith(b"-----BEGIN COURIER ENCRYPTED KEY-----")
    blob = _blob(path)
    assert blob[:5] == b"CCKEY"
    assert blob[5] == 1                         # format version
    # The private key must not appear in the file in any readable form.
    der = rsa_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    assert der[-64:] not in bytes(blob)


def test_salt_and_nonce_fresh_each_save(tmp_path, rsa_key, passphrase):
    a = _blob(_save(tmp_path, rsa_key, passphrase, name="a.key"))
    b = _blob(_save(tmp_path, rsa_key, passphrase, name="b.key"))
    # Layout for label "sign": magic[0:5] ver[5] len[6] label[7:11] n,r,p[11:14]
    #                          salt[14:30] nonce[30:42] ciphertext[42:]
    assert a[:14] == b[:14]           # magic, version, label, scrypt params
    assert a[14:30] != b[14:30]       # salt differs
    assert a[30:42] != b[30:42]       # nonce differs
    assert a[42:] != b[42:]           # so the ciphertext differs too


def test_production_scrypt_cost(tmp_path, rsa_key, passphrase):
    assert keystore.PRODUCTION_SCRYPT_LOG2N == 17
    path = _save(tmp_path, rsa_key, passphrase, scrypt_log2n=keystore.PRODUCTION_SCRYPT_LOG2N)
    blob = _blob(path)
    assert blob[11] == 17                       # log2_n byte after "CCKEY",1,4,"sign"
    assert load_private_key(path, passphrase, label="sign").key_size == 3072


# --- wrong secret, tampering, swapping -----------------------------------------

def test_wrong_passphrase_rejected(tmp_path, rsa_key, passphrase):
    path = _save(tmp_path, rsa_key, passphrase)
    with pytest.raises(WrongPassphraseError):
        load_private_key(path, b"not the passphrase", label="sign")


def test_modified_ciphertext_rejected(tmp_path, rsa_key, passphrase):
    path = _save(tmp_path, rsa_key, passphrase)
    blob = _blob(path)
    blob[-100] ^= 0x01
    _write_blob(path, blob)
    with pytest.raises(WrongPassphraseError):
        load_private_key(path, passphrase, label="sign")


def test_modified_salt_rejected(tmp_path, rsa_key, passphrase):
    path = _save(tmp_path, rsa_key, passphrase)
    blob = _blob(path)
    blob[20] ^= 0x01                            # inside the salt
    _write_blob(path, blob)
    with pytest.raises(WrongPassphraseError):
        load_private_key(path, passphrase, label="sign")


def test_relabelled_file_rejected(tmp_path, rsa_key, passphrase):
    """Editing the label in the header (sign -> sigx) breaks the GCM tag."""
    path = _save(tmp_path, rsa_key, passphrase)
    blob = _blob(path)
    blob[10:11] = b"x"                          # "sign" -> "sigx"
    _write_blob(path, blob)
    with pytest.raises(WrongPassphraseError):
        load_private_key(path, passphrase, label="sigx")


def test_swapped_key_file_rejected(tmp_path, rsa_key, passphrase):
    """enc.key copied over sign.key is refused even with the right passphrase."""
    enc = _save(tmp_path, rsa_key, passphrase, name="enc.key", label="enc")
    with pytest.raises(KeyLoadError, match="expected 'sign'"):
        load_private_key(enc, passphrase, label="sign")


def test_weakened_scrypt_cost_rejected(tmp_path, rsa_key, passphrase):
    path = _save(tmp_path, rsa_key, passphrase)
    blob = _blob(path)
    blob[11] = 10                               # 2**10: below the allowed minimum
    _write_blob(path, blob)
    with pytest.raises(KeyLoadError, match="scrypt"):
        load_private_key(path, passphrase, label="sign")


def test_huge_scrypt_cost_rejected(tmp_path, rsa_key, passphrase):
    path = _save(tmp_path, rsa_key, passphrase)
    blob = _blob(path)
    blob[11] = 30                               # 2**30 would need 128 GiB of memory
    _write_blob(path, blob)
    with pytest.raises(KeyLoadError, match="scrypt"):
        load_private_key(path, passphrase, label="sign")


@pytest.mark.parametrize("content", [
    b"",
    b"not a key file at all",
    b"-----BEGIN COURIER ENCRYPTED KEY-----\n!!!!\n-----END COURIER ENCRYPTED KEY-----\n",
    keystore._armor(b"XXXXX" + bytes(60)),      # wrong magic
    keystore._armor(b"CCKEY\x02\x04sign"),      # wrong version, truncated
    keystore._armor(b"CCKEY\x01\x04sign\x0e\x08\x01"),  # truncated after params
])
def test_malformed_files_rejected(tmp_path, passphrase, content):
    keys = tmp_path / "keys"
    keys.mkdir(mode=0o700)
    path = keys / "bad.key"
    path.write_bytes(content)
    os.chmod(path, 0o600)
    with pytest.raises(KeyLoadError):
        load_private_key(path, passphrase, label="sign")


def test_pkcs8_pem_key_rejected(tmp_path, rsa_key, passphrase):
    """A standard PEM key (even an encrypted one) is not accepted in place of our format."""
    keys = tmp_path / "keys"
    keys.mkdir(mode=0o700)
    path = keys / "sign.key"
    path.write_bytes(rsa_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase)))
    os.chmod(path, 0o600)
    with pytest.raises(KeyLoadError):
        load_private_key(path, passphrase, label="sign")


# --- file system checks --------------------------------------------------------

def test_loose_file_permissions_rejected(tmp_path, rsa_key, passphrase):
    path = _save(tmp_path, rsa_key, passphrase)
    os.chmod(path, 0o644)
    with pytest.raises(InsecurePermissionsError):
        load_private_key(path, passphrase, label="sign")


def test_loose_directory_permissions_rejected(tmp_path, rsa_key, passphrase):
    path = _save(tmp_path, rsa_key, passphrase)
    os.chmod(path.parent, 0o755)
    with pytest.raises(InsecurePermissionsError):
        load_private_key(path, passphrase, label="sign")


def test_symlinked_key_rejected(tmp_path, rsa_key, passphrase):
    real = _save(tmp_path, rsa_key, passphrase, name="real.key")
    link = tmp_path / "keys" / "link.key"
    link.symlink_to(real)
    with pytest.raises(InsecurePermissionsError):
        load_private_key(link, passphrase, label="sign")


def test_missing_file(tmp_path, passphrase):
    with pytest.raises(KeyLoadError):
        load_private_key(tmp_path / "nope.key", passphrase, label="sign")


# --- input checks on save ------------------------------------------------------

def test_refuses_overwrite(tmp_path, rsa_key, passphrase):
    path = _save(tmp_path, rsa_key, passphrase)
    with pytest.raises(KeyStoreError):
        save_private_key(path, rsa_key, passphrase, label="sign")
    save_private_key(path, rsa_key, passphrase, label="sign", overwrite=True)


def test_short_passphrase_rejected(tmp_path, rsa_key):
    with pytest.raises(KeyStoreError):
        _save(tmp_path, rsa_key, b"short")


def test_wrong_key_size_rejected(tmp_path, passphrase):
    small = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(KeyLoadError):
        _save(tmp_path, small, passphrase)


@pytest.mark.parametrize("label", ["", "Sign", "a/b", "x" * 33])
def test_bad_label_rejected(tmp_path, rsa_key, passphrase, label):
    with pytest.raises(KeyStoreError):
        _save(tmp_path, rsa_key, passphrase, label=label)
