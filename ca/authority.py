"""The Courier certificate authority: creating and loading the CA (design notes, sections 3-4).

The CA lives in its own directory (default ./ca-data, git-ignored), mode 0700:

    ca-data/ca.key   CA private key, encrypted with the CA passphrase (keystore format)
    ca-data/ca.crt   self-signed CA certificate; this file becomes every device's trust anchor

Later pieces add the issued-certificate index and CRL state to the same directory.
"""
from __future__ import annotations

import datetime
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from courier.errors import CAError, CertificateError
from courier.pki.certs import check_ca_certificate, load_certificate, save_certificate
from courier.storage.keystore import (
    ensure_private_dir,
    generate_rsa_key,
    load_private_key,
    save_private_key,
)

CA_KEY_LABEL = "ca"
CA_VALIDITY_DAYS = 730               # 2 years
CLOCK_SKEW = datetime.timedelta(minutes=5)
ORGANIZATION = "Clipboard Courier"
_CA_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .\-]{0,63}$")


@dataclass(frozen=True)
class CAPaths:
    root: Path

    @property
    def key(self) -> Path:
        return self.root / "ca.key"

    @property
    def cert(self) -> Path:
        return self.root / "ca.crt"


@dataclass(frozen=True)
class CertificateAuthority:
    """A loaded, unlocked CA: its private key and certificate."""

    key: rsa.RSAPrivateKey
    cert: x509.Certificate


def init_ca(
    root: Path,
    name: str,
    passphrase: bytes,
    *,
    validity_days: int = CA_VALIDITY_DAYS,
    now: datetime.datetime | None = None,
) -> x509.Certificate:
    """Create a new CA key and self-signed certificate in `root`.

    Refuses to run if a CA already exists there: replacing a CA silently would
    invalidate every device's trust anchor.
    """
    if not isinstance(name, str) or not _CA_NAME_RE.fullmatch(name):
        raise CAError("CA name must be 1-64 characters: letters, digits, spaces, '.' and '-'")
    if not 1 <= validity_days <= 3650:
        raise CAError("CA validity must be between 1 and 3650 days")

    paths = CAPaths(Path(root))
    if paths.key.exists() or paths.cert.exists():
        raise CAError(f"a CA already exists in {paths.root}; refusing to replace it")
    ensure_private_dir(paths.root)

    now = now or datetime.datetime.now(datetime.timezone.utc)
    key = generate_rsa_key()
    cert = _build_ca_certificate(key, name, now, validity_days)
    check_ca_certificate(cert)       # never write out a CA certificate we would reject

    save_private_key(paths.key, key, passphrase, label=CA_KEY_LABEL)
    try:
        save_certificate(paths.cert, cert)
    except BaseException:
        paths.key.unlink(missing_ok=True)   # don't leave a key without its certificate
        raise
    return cert


def load_ca_certificate(root: Path) -> x509.Certificate:
    """Load and check the CA certificate. Needs no passphrase."""
    cert = load_certificate(CAPaths(Path(root)).cert)
    check_ca_certificate(cert)
    return cert


def load_ca(root: Path, passphrase: bytes) -> CertificateAuthority:
    """Unlock the CA: load its key and certificate and check that they belong together."""
    paths = CAPaths(Path(root))
    cert = load_ca_certificate(paths.root)
    key = load_private_key(paths.key, passphrase, label=CA_KEY_LABEL)
    if key.public_key().public_numbers() != cert.public_key().public_numbers():
        raise CertificateError("ca.key does not match ca.crt")
    return CertificateAuthority(key=key, cert=cert)


def _build_ca_certificate(
    key: rsa.RSAPrivateKey,
    name: str,
    now: datetime.datetime,
    validity_days: int,
) -> x509.Certificate:
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)                       # self-signed: issuer == subject
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - CLOCK_SKEW)          # tolerate slightly slow clocks
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
