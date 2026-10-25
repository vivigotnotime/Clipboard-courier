"""Device identities.

A device is identified by a URI in its certificates' Subject Alternative Name:

    courier://user/<user>/device/<device>

<user> and <device> use only a-z, 0-9 and '-', 1 to 32 characters each
(design notes, section 2). The URI string is the device ID used everywhere.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from cryptography import x509

from courier.errors import IdentityError

_NAME = r"[a-z0-9-]{1,32}"
_NAME_RE = re.compile(rf"^{_NAME}$")
_URI_RE = re.compile(rf"^courier://user/({_NAME})/device/({_NAME})$")


@dataclass(frozen=True)
class DeviceId:
    """A validated (user, device) pair. Construct it with parse() or create()."""

    user: str
    device: str

    def __post_init__(self) -> None:
        # Validate here as well, so a DeviceId can never exist in an invalid state.
        for label, value in (("user", self.user), ("device", self.device)):
            if not isinstance(value, str) or not _NAME_RE.fullmatch(value):
                raise IdentityError(
                    f"invalid {label} name {value!r}: use 1-32 characters from a-z, 0-9 and '-'"
                )

    @property
    def uri(self) -> str:
        return f"courier://user/{self.user}/device/{self.device}"

    def __str__(self) -> str:
        return self.uri

    @classmethod
    def create(cls, user: str, device: str) -> "DeviceId":
        return cls(user, device)

    @classmethod
    def parse(cls, uri: str) -> "DeviceId":
        """Parse a device ID string, rejecting anything that is not exactly canonical."""
        if not isinstance(uri, str):
            raise IdentityError("device ID must be a string")
        match = _URI_RE.fullmatch(uri)
        if match is None:
            raise IdentityError(f"malformed device ID {uri!r}")
        return cls(match.group(1), match.group(2))

    def to_san(self) -> x509.SubjectAlternativeName:
        """The SAN extension value to put in this device's certificates."""
        return x509.SubjectAlternativeName([x509.UniformResourceIdentifier(self.uri)])


def device_id_from_certificate(cert: x509.Certificate) -> DeviceId:
    """Extract the device ID from a certificate's SAN.

    The certificate must contain exactly one URI SAN and it must be a valid
    Courier device ID. Anything else is rejected rather than guessed at.
    """
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        raise IdentityError("certificate has no Subject Alternative Name") from None
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1:
        raise IdentityError(f"certificate must have exactly one URI SAN, found {len(uris)}")
    return DeviceId.parse(uris[0])
