"""Certificate helpers shared by the CA tool and devices.

- Fingerprints: SHA-256 over the certificate's DER encoding. This is the value
  people compare out of band to install the trust anchor (design notes, section 4).
- Loading and saving PEM certificate files strictly (exactly one certificate).
- Checking that a certificate is a well-formed Courier CA certificate.
"""
from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from courier.errors import CertificateError
from courier.storage.files import atomic_write

MAX_CERT_FILE_SIZE = 64 * 1024
PEM_CERT_BEGIN = b"-----BEGIN CERTIFICATE-----"


def fingerprint(cert: x509.Certificate) -> bytes:
    """SHA-256 of the certificate's DER bytes (32 bytes)."""
    return cert.fingerprint(hashes.SHA256())


def format_fingerprint(fp: bytes) -> str:
    """Show a fingerprint as 16 groups of 4 hex digits, easy to read aloud.

    e.g. '3F2A 9C11 ... 07BD'
    """
    hexed = fp.hex().upper()
    return " ".join(hexed[i:i + 4] for i in range(0, len(hexed), 4))


def load_certificate(path: Path) -> x509.Certificate:
    """Load a PEM file that contains exactly one certificate and nothing else."""
    path = Path(path)
    if not path.is_file():
        raise CertificateError(f"certificate file not found: {path}")
    if path.stat().st_size > MAX_CERT_FILE_SIZE:
        raise CertificateError(f"{path} is too large to be a certificate file")
    data = path.read_bytes()
    if data.count(PEM_CERT_BEGIN) != 1:
        raise CertificateError(f"{path} must contain exactly one PEM certificate")
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        raise CertificateError(f"{path} is not a valid PEM certificate") from None


def save_certificate(path: Path, cert: x509.Certificate, *, overwrite: bool = False) -> None:
    """Write a certificate as PEM (mode 0644: certificates are public)."""
    try:
        atomic_write(Path(path), cert.public_bytes(serialization.Encoding.PEM),
                     mode=0o644, overwrite=overwrite)
    except FileExistsError as exc:
        raise CertificateError(str(exc)) from None


def check_ca_certificate(cert: x509.Certificate) -> None:
    """Raise CertificateError unless `cert` is a valid Courier CA certificate.

    Checks: RSA-3072 key, self-signed with a valid signature, basicConstraints
    CA:TRUE with pathlen 0 (critical), keyUsage keyCertSign + cRLSign only (critical).
    Validity dates are checked separately, at the time of use.
    """
    key = cert.public_key()
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 3072:
        raise CertificateError("CA certificate must have an RSA-3072 key")
    if cert.issuer != cert.subject:
        raise CertificateError("CA certificate is not self-issued")
    try:
        cert.verify_directly_issued_by(cert)
    except Exception:  # InvalidSignature, ValueError, TypeError depending on the fault
        raise CertificateError("CA certificate's self-signature is invalid") from None

    bc = _extension(cert, x509.BasicConstraints)
    if not bc.critical or not bc.value.ca or bc.value.path_length != 0:
        raise CertificateError("CA certificate needs critical basicConstraints CA:TRUE, pathlen:0")

    ku = _extension(cert, x509.KeyUsage)
    v = ku.value
    if not ku.critical or not v.key_cert_sign or not v.crl_sign:
        raise CertificateError("CA certificate needs critical keyUsage keyCertSign and cRLSign")
    if v.digital_signature or v.content_commitment or v.key_encipherment \
            or v.data_encipherment or v.key_agreement:
        raise CertificateError("CA certificate keyUsage must only allow certificate and CRL signing")


def _extension(cert: x509.Certificate, ext_type):
    try:
        return cert.extensions.get_extension_for_class(ext_type)
    except x509.ExtensionNotFound:
        raise CertificateError(f"certificate is missing the {ext_type.__name__} extension") from None
