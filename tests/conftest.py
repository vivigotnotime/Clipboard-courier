"""Shared test fixtures.

RSA-3072 generation is slow, so keys are generated once per test session and reused.
scrypt is deliberately slow too, so tests lower its cost to the minimum allowed
(2**14); one test checks the production setting separately.
"""
import pytest

from courier.storage import keystore

PASSPHRASE = b"correct horse battery"


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    monkeypatch.setattr(keystore, "DEFAULT_SCRYPT_LOG2N", keystore.MIN_SCRYPT_LOG2N)


@pytest.fixture(scope="session")
def rsa_key():
    return keystore.generate_rsa_key()


@pytest.fixture(scope="session")
def other_rsa_key():
    return keystore.generate_rsa_key()


@pytest.fixture
def passphrase():
    return PASSPHRASE
