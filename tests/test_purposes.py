from courier.pki.purposes import DEVICE_PURPOSES, PROFILES, KeyPurpose


def test_every_purpose_has_a_profile():
    assert set(PROFILES) == set(KeyPurpose)


def test_ekus_are_distinct():
    ekus = [PROFILES[p].eku for p in KeyPurpose]
    assert len(set(ekus)) == len(ekus)


def test_no_device_key_can_sign_certificates_or_crls():
    for p in KeyPurpose:
        ku = PROFILES[p].key_usage
        assert not ku.key_cert_sign and not ku.crl_sign


def test_key_separation():
    assert PROFILES[KeyPurpose.ENCRYPTION].key_usage.key_encipherment
    assert not PROFILES[KeyPurpose.ENCRYPTION].key_usage.digital_signature
    assert not PROFILES[KeyPurpose.SIGNING].key_usage.key_encipherment
    assert not PROFILES[KeyPurpose.TLS].key_usage.key_encipherment


def test_device_purposes():
    assert DEVICE_PURPOSES == (KeyPurpose.TLS, KeyPurpose.SIGNING, KeyPurpose.ENCRYPTION)
