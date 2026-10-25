import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from courier.errors import IdentityError
from courier.identity import DeviceId, device_id_from_certificate


def test_round_trip():
    d = DeviceId.create("alice", "laptop1")
    assert d.uri == "courier://user/alice/device/laptop1"
    assert DeviceId.parse(d.uri) == d


@pytest.mark.parametrize("uri", [
    "",
    "courier://user/alice",
    "courier://user/Alice/device/laptop1",          # uppercase
    "courier://user/alice/device/laptop_1",         # underscore
    "courier://user/alice/device/laptop1/",         # trailing slash
    "courier://user/alice/device/laptop1\n",        # trailing newline
    " courier://user/alice/device/laptop1",         # leading space
    "https://user/alice/device/laptop1",            # wrong scheme
    "courier://user/" + "a" * 33 + "/device/x",     # too long
    "courier://user//device/laptop1",               # empty user
    "courier://user/alice/device/lap%74op1",        # percent-encoding
])
def test_parse_rejects_malformed(uri):
    with pytest.raises(IdentityError):
        DeviceId.parse(uri)


def test_constructor_validates():
    with pytest.raises(IdentityError):
        DeviceId("alice", "bad/device")


def _cert_with_san(key, san):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
    )
    if san is not None:
        builder = builder.add_extension(san, critical=False)
    return builder.sign(key, hashes.SHA256())


def test_device_id_from_certificate(rsa_key):
    d = DeviceId.create("bob", "desk-2")
    cert = _cert_with_san(rsa_key, d.to_san())
    assert device_id_from_certificate(cert) == d


def test_certificate_without_san_rejected(rsa_key):
    with pytest.raises(IdentityError):
        device_id_from_certificate(_cert_with_san(rsa_key, None))


def test_certificate_with_two_uris_rejected(rsa_key):
    san = x509.SubjectAlternativeName([
        x509.UniformResourceIdentifier("courier://user/a/device/b"),
        x509.UniformResourceIdentifier("courier://user/c/device/d"),
    ])
    with pytest.raises(IdentityError):
        device_id_from_certificate(_cert_with_san(rsa_key, san))


def test_certificate_with_bad_uri_rejected(rsa_key):
    san = x509.SubjectAlternativeName([x509.UniformResourceIdentifier("https://example.com")])
    with pytest.raises(IdentityError):
        device_id_from_certificate(_cert_with_san(rsa_key, san))
