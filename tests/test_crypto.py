import pytest

from passwordmanager.core import crypto

PW = "correct horse battery"


@pytest.fixture
def blob(fast_params):
    salt = crypto.new_salt()
    key = crypto.derive_key(PW, salt, fast_params)
    return crypto.encrypt(key, b"secret payload", salt, fast_params)


def test_roundtrip(blob):
    plaintext, _, header = crypto.decrypt(PW, blob)
    assert plaintext == b"secret payload"
    assert header.version == crypto.FORMAT_VERSION


def test_wrong_password(blob):
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt("not the password", blob)


def test_tampered_ciphertext_detected(blob):
    bad = bytearray(blob)
    bad[-1] ^= 0x01
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(PW, bytes(bad))


def test_tampered_header_detected(blob):
    # Flip a salt byte: either key derivation or the AAD check must fail.
    bad = bytearray(blob)
    bad[crypto.HEADER_SIZE - crypto.NONCE_LEN - 1] ^= 0x01
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(PW, bytes(bad))


def test_fresh_nonce_every_encryption(fast_params):
    salt = crypto.new_salt()
    key = crypto.derive_key(PW, salt, fast_params)
    nonces = {
        crypto.parse_header(crypto.encrypt(key, b"x", salt, fast_params)).nonce for _ in range(200)
    }
    assert len(nonces) == 200


def test_bad_magic_rejected(blob):
    with pytest.raises(crypto.InvalidFormat):
        crypto.decrypt(PW, b"XXXX" + blob[4:])


def test_truncated_file_rejected():
    with pytest.raises(crypto.InvalidFormat):
        crypto.decrypt(PW, b"PMGR\x01")


def test_absurd_kdf_params_rejected(fast_params):
    header = crypto._HEADER.pack(
        crypto.MAGIC, crypto.FORMAT_VERSION, 1, 2**31, 1, b"s" * 16, b"n" * 12
    )
    with pytest.raises(crypto.InvalidFormat):
        crypto.parse_header(header + b"\x00" * 32)


def _header(time_cost, memory, parallelism):
    return crypto._HEADER.pack(
        crypto.MAGIC, crypto.FORMAT_VERSION, time_cost, memory, parallelism, b"s" * 16, b"n" * 12
    ) + b"\x00" * 32


def test_kdf_memory_above_256_mib_rejected():  # F-A
    with pytest.raises(crypto.InvalidFormat):
        crypto.parse_header(_header(3, 256 * 1024 + 1, 4))
    crypto.parse_header(_header(3, 256 * 1024, 4))  # the limit itself is fine


def test_kdf_time_cost_above_ten_rejected():  # F-A
    with pytest.raises(crypto.InvalidFormat):
        crypto.parse_header(_header(11, 64 * 1024, 4))


def test_memory_below_8x_parallelism_is_rejected_not_a_crash():  # F-B
    with pytest.raises(crypto.InvalidFormat):
        crypto.decrypt(PW, _header(1, 8, 2))
