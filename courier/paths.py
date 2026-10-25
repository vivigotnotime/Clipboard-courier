"""Where a device keeps its files (design notes, section 9).

Default location is $XDG_DATA_HOME/courier, normally ~/.local/share/courier.
Tests pass their own temporary directory instead.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from courier.pki.purposes import KeyPurpose


def default_data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(Path.home(), ".local", "share")
    return Path(base) / "courier"


@dataclass(frozen=True)
class DevicePaths:
    root: Path

    @property
    def keys(self) -> Path:
        return self.root / "keys"

    @property
    def certs(self) -> Path:
        return self.root / "certs"

    @property
    def state(self) -> Path:
        return self.root / "state"

    @property
    def logs(self) -> Path:
        return self.root / "logs"

    def key_file(self, purpose: KeyPurpose) -> Path:
        return self.keys / f"{purpose.value}.key"

    def cert_file(self, purpose: KeyPurpose) -> Path:
        return self.certs / f"{purpose.value}.crt"

    @property
    def ca_cert(self) -> Path:
        return self.certs / "ca.crt"

    @property
    def crl(self) -> Path:
        return self.state / "crl.pem"

    @property
    def crl_number(self) -> Path:
        return self.state / "crl_number"

    @property
    def replay_db(self) -> Path:
        return self.state / "replay.sqlite3"
