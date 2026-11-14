import datetime
import os
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from ca import authority
from ca.__main__ import main
from ca.authority import CAPaths, init_ca, load_ca, load_ca_certificate
from courier.errors import CAError, CertificateError, WrongPassphraseError
from courier.pki.certs import (
    check_ca_certificate,
    fingerprint,
    format_fingerprint,
    save_certificate,
)
from courier.storage.keystore import save_private_key

NAME = "Courier Test CA"


@pytest.fixture
def ca_dir(tmp_path, passphrase):
    root = tmp_path / "ca-data"
    init_ca(root, NAME, passphrase)
    return root


# --- init ------------------------------------------------------------------------

def test_init_creates_files_with_safe_permissions(ca_dir):
    paths = CAPaths(ca_dir)
    assert stat.S_IMODE(os.stat(ca_dir).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(paths.key).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(paths.cert).st_mode) == 0o644
    assert paths.key.read_bytes().startswith(b"-----BEGIN COURIER ENCRYPTED KEY-----")


def test_ca_certificate_profile(ca_dir):
    cert = load_ca_certificate(ca_dir)
    assert cert.subject == cert.issuer
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == NAME
    assert cert.public_key().key_size == 3072
    assert isinstance(cert.signature_hash_algorithm, hashes.SHA256)

    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical and bc.value.ca and bc.value.path_length == 0

    ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.critical and ku.value.key_cert_sign and ku.value.crl_sign
    assert not ku.value.digital_signature and not ku.value.key_encipherment

    ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    assert aki.key_identifier == ski.digest


def test_validity_period(tmp_path, passphrase):
    now = datetime.datetime(2026, 11, 9, 12, 0, tzinfo=datetime.timezone.utc)
    cert = init_ca(tmp_path / "ca", NAME, passphrase, now=now)
    assert cert.not_valid_before_utc == now - datetime.timedelta(minutes=5)
    assert cert.not_valid_after_utc == now + datetime.timedelta(days=730)


def test_refuses_to_replace_existing_ca(ca_dir, passphrase):
    before = CAPaths(ca_dir).cert.read_bytes()
    with pytest.raises(CAError):
        init_ca(ca_dir, NAME, passphrase)
    assert CAPaths(ca_dir).cert.read_bytes() == before


@pytest.mark.parametrize("name", ["", " leading space", "bad/name", "x" * 65, "évil"])
def test_bad_ca_name_rejected(tmp_path, passphrase, name):
    with pytest.raises(CAError):
        init_ca(tmp_path / "ca", name, passphrase)


def test_each_init_makes_a_different_ca(tmp_path, passphrase):
    a = init_ca(tmp_path / "a", NAME, passphrase)
    b = init_ca(tmp_path / "b", NAME, passphrase)
    assert fingerprint(a) != fingerprint(b)


# --- load -------------------------------------------------------------------------

def test_load_ca_round_trip(ca_dir, passphrase):
    ca = load_ca(ca_dir, passphrase)
    assert ca.key.public_key().public_numbers() == ca.cert.public_key().public_numbers()


def test_load_ca_wrong_passphrase(ca_dir):
    with pytest.raises(WrongPassphraseError):
        load_ca(ca_dir, b"wrong passphrase")


def test_load_ca_mismatched_key_rejected(ca_dir, passphrase, other_rsa_key):
    save_private_key(CAPaths(ca_dir).key, other_rsa_key, passphrase, label="ca", overwrite=True)
    with pytest.raises(CertificateError, match="does not match"):
        load_ca(ca_dir, passphrase)


def test_load_ca_rejects_device_key_file(ca_dir, passphrase, other_rsa_key):
    """A device's sign.key dropped in as ca.key is refused by its label."""
    from courier.errors import KeyLoadError
    save_private_key(CAPaths(ca_dir).key, other_rsa_key, passphrase, label="sign", overwrite=True)
    with pytest.raises(KeyLoadError):
        load_ca(ca_dir, passphrase)


def test_replaced_ca_certificate_detected(ca_dir, tmp_path, passphrase):
    """Swapping in another CA's certificate changes the fingerprint and fails the key match."""
    original = load_ca_certificate(ca_dir)
    other = init_ca(tmp_path / "other", NAME, passphrase)
    save_certificate(CAPaths(ca_dir).cert, other, overwrite=True)
    assert fingerprint(load_ca_certificate(ca_dir)) != fingerprint(original)
    with pytest.raises(CertificateError):
        load_ca(ca_dir, passphrase)


def test_two_certificates_in_file_rejected(ca_dir):
    path = CAPaths(ca_dir).cert
    path.write_bytes(path.read_bytes() * 2)
    with pytest.raises(CertificateError, match="exactly one"):
        load_ca_certificate(ca_dir)


# --- check_ca_certificate against bad CA certificates -------------------------------

def _cert(key, *, bc=None, ku=None, issuer_cn=None, sign_with=None):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]) if issuer_cn else subject
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
         .public_key(key.public_key()).serial_number(1)
         .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)))
    if bc is not None:
        b = b.add_extension(bc[0], critical=bc[1])
    if ku is not None:
        b = b.add_extension(ku[0], critical=ku[1])
    return b.sign(sign_with or key, hashes.SHA256())


def _ku(**on):
    flags = dict(digital_signature=False, content_commitment=False, key_encipherment=False,
                 data_encipherment=False, key_agreement=False, key_cert_sign=False,
                 crl_sign=False, encipher_only=False, decipher_only=False)
    flags.update(on)
    return x509.KeyUsage(**flags)


GOOD_BC = (x509.BasicConstraints(ca=True, path_length=0), True)
GOOD_KU = (_ku(key_cert_sign=True, crl_sign=True), True)


def test_good_handmade_ca_accepted(rsa_key):
    check_ca_certificate(_cert(rsa_key, bc=GOOD_BC, ku=GOOD_KU))


@pytest.mark.parametrize("kwargs", [
    dict(bc=None, ku=GOOD_KU),                                                  # no basicConstraints
    dict(bc=(x509.BasicConstraints(ca=False, path_length=None), True), ku=GOOD_KU),  # not a CA
    dict(bc=(x509.BasicConstraints(ca=True, path_length=None), True), ku=GOOD_KU),   # no pathlen limit
    dict(bc=(x509.BasicConstraints(ca=True, path_length=0), False), ku=GOOD_KU),     # not critical
    dict(bc=GOOD_BC, ku=None),                                                  # no keyUsage
    dict(bc=GOOD_BC, ku=(_ku(key_cert_sign=True), True)),                       # cannot sign CRLs
    dict(bc=GOOD_BC, ku=(_ku(key_cert_sign=True, crl_sign=True, digital_signature=True), True)),
    dict(bc=GOOD_BC, ku=GOOD_KU, issuer_cn="someone else"),                     # not self-issued
])
def test_bad_ca_certificates_rejected(rsa_key, kwargs):
    with pytest.raises(CertificateError):
        check_ca_certificate(_cert(rsa_key, **kwargs))


def test_ca_certificate_with_bad_signature_rejected(rsa_key, other_rsa_key):
    with pytest.raises(CertificateError, match="self-signature"):
        check_ca_certificate(_cert(rsa_key, bc=GOOD_BC, ku=GOOD_KU, sign_with=other_rsa_key))


# --- fingerprint formatting -------------------------------------------------------

def test_format_fingerprint():
    text = format_fingerprint(bytes(range(32)))
    assert text.startswith("0001 0203 0405")
    groups = text.split(" ")
    assert len(groups) == 16 and all(len(g) == 4 for g in groups)


# --- command line -----------------------------------------------------------------

def test_cli_init_and_fingerprint(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "cli passphrase")
    root = tmp_path / "ca-data"
    assert main(["init", "--dir", str(root), "--name", "CLI Test CA"]) == 0
    init_out = capsys.readouterr().out

    assert main(["fingerprint", "--dir", str(root)]) == 0
    fp_out = capsys.readouterr().out

    expected = format_fingerprint(fingerprint(load_ca_certificate(root)))
    assert expected in init_out and expected in fp_out


def test_cli_mismatched_passphrases(tmp_path, monkeypatch, capsys):
    answers = iter(["first passphrase", "second passphrase"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    root = tmp_path / "ca-data"
    assert main(["init", "--dir", str(root), "--name", "CLI Test CA"]) == 1
    assert "do not match" in capsys.readouterr().err
    assert not root.exists()


def test_cli_cancel_at_prompt(tmp_path, monkeypatch, capsys):
    def cancel(prompt=""):
        raise EOFError
    monkeypatch.setattr("getpass.getpass", cancel)
    root = tmp_path / "ca-data"
    assert main(["init", "--dir", str(root), "--name", "CLI Test CA"]) == 1
    assert "cancelled" in capsys.readouterr().err
    assert not root.exists()


def test_cli_fingerprint_without_ca(tmp_path, capsys):
    assert main(["fingerprint", "--dir", str(tmp_path / "missing")]) == 1
    assert "not found" in capsys.readouterr().err
