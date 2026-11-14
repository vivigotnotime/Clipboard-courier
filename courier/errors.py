"""Exception types shared across Clipboard Courier.

Every error raised on purpose by Courier code derives from CourierError, so
callers (CLI, GUI) can catch one type and show a clean message instead of a
traceback.
"""


class CourierError(Exception):
    """Base class for all deliberate Courier errors."""


class IdentityError(CourierError):
    """A device identity string or certificate SAN is malformed."""


class KeyStoreError(CourierError):
    """Base class for problems saving or loading private keys."""


class InsecurePermissionsError(KeyStoreError):
    """A key file or directory is readable or writable by other users."""


class WrongPassphraseError(KeyStoreError):
    """The passphrase did not decrypt the key file."""


class KeyLoadError(KeyStoreError):
    """A key file is missing, malformed, for the wrong purpose, or the wrong kind of key."""


class CertificateError(CourierError):
    """A certificate file is missing or malformed, or a certificate fails a check."""


class CAError(CourierError):
    """A certificate-authority operation cannot be carried out."""
