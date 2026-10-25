"""Shared test fixtures.

RSA-3072 generation is slow, so one key is generated per test session and reused.
"""
import pytest

from courier.storage.keystore import generate_rsa_key

PASSPHRASE = b"correct horse battery"


@pytest.fixture(scope="session")
def rsa_key():
    return generate_rsa_key()


@pytest.fixture
def passphrase():
    return PASSPHRASE
