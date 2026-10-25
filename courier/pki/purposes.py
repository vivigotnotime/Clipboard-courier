"""Key purposes and the certificate profile for each (design notes, section 3).

Each device has three key pairs, and each key is locked to one job by the
keyUsage and extendedKeyUsage extensions of its certificate. The CA writes
these extensions from this table, and validation checks them against it, so
both sides agree from a single source.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

# Private OIDs minted from random UUIDs under the 2.25 arc (ITU-T X.667).
COURIER_SIGNING_OID = x509.ObjectIdentifier("2.25.72588524155360460612940102899727988603")
COURIER_CONTENT_ENCRYPTION_OID = x509.ObjectIdentifier(
    "2.25.313126030033596718424735362180916615048"
)


class KeyPurpose(enum.Enum):
    TLS = "tls"                # device's mTLS client key
    SIGNING = "sign"           # RSA-PSS signatures on transfer records
    ENCRYPTION = "enc"         # RSA-OAEP unwrapping of per-transfer AES keys
    RELAY_TLS = "relay-tls"    # the relay's TLS server key


@dataclass(frozen=True)
class CertProfile:
    eku: x509.ObjectIdentifier
    key_usage: x509.KeyUsage


def _key_usage(*, digital_signature=False, content_commitment=False,
               key_encipherment=False) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=content_commitment,
        key_encipherment=key_encipherment,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


PROFILES: dict[KeyPurpose, CertProfile] = {
    KeyPurpose.TLS: CertProfile(
        eku=ExtendedKeyUsageOID.CLIENT_AUTH,
        key_usage=_key_usage(digital_signature=True),
    ),
    KeyPurpose.SIGNING: CertProfile(
        eku=COURIER_SIGNING_OID,
        key_usage=_key_usage(digital_signature=True, content_commitment=True),
    ),
    KeyPurpose.ENCRYPTION: CertProfile(
        eku=COURIER_CONTENT_ENCRYPTION_OID,
        key_usage=_key_usage(key_encipherment=True),
    ),
    KeyPurpose.RELAY_TLS: CertProfile(
        eku=ExtendedKeyUsageOID.SERVER_AUTH,
        key_usage=_key_usage(digital_signature=True),
    ),
}

# The three purposes every ordinary device enrolls with.
DEVICE_PURPOSES = (KeyPurpose.TLS, KeyPurpose.SIGNING, KeyPurpose.ENCRYPTION)
