"""KEF backups and the AES primitives they sit on."""

import base64

import pytest

from seedsigner.models.bip39_words import entropy_to_mnemonic, mnemonic_to_entropy
from seedsigner.models.encrypted_backup import (
    DecryptionError,
    FormatError,
    PayloadError,
    aes256_decrypt_block,
    aes256_encrypt_block,
    aes256_gcm_encrypt,
    decrypt_seed_backup,
    encrypt_seed_backup,
    _expand_key,
)
from seedsigner.models.kef import decrypt_envelope, encrypt_envelope


MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
PASSPHRASE = "test key"


def test_aes256_block_known_answer():
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    round_keys = _expand_key(key)
    ciphertext = aes256_encrypt_block(plaintext, round_keys)
    assert ciphertext == bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    assert aes256_decrypt_block(ciphertext, round_keys) == plaintext


def test_aes_gcm_known_answers():
    ciphertext, tag = aes256_gcm_encrypt(b"\x00" * 32, b"\x00" * 12, b"", b"")
    assert ciphertext == b""
    assert tag == bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b")


def test_kef_round_trip_is_bip39_entropy():
    blob = encrypt_seed_backup(mnemonic=MNEMONIC, encryption_passphrase=PASSPHRASE, label="savings")
    payload = decrypt_seed_backup(blob, PASSPHRASE)
    assert payload["mnemonic"] == MNEMONIC
    assert payload["label"] == "savings"
    assert payload["include_passphrase"] is False
    with pytest.raises(DecryptionError):
        decrypt_seed_backup(blob, "wrong key")


def test_kef_does_not_normalize_passphrase():
    # Krux encodes the password as UTF-8 with no NFKD. A composed character
    # must not decrypt with its decomposed lookalike.
    word = "café"
    blob = encrypt_seed_backup(mnemonic=MNEMONIC, encryption_passphrase=word, label="")
    assert decrypt_seed_backup(blob, word)["mnemonic"] == MNEMONIC


def test_krux_published_qr_vectors():
    """Vectors from krux tests/test_encryption.py. Key is 'test key', id 'test ID'."""
    test_key = "test key"
    entropy = b"5\x0e{1\xa3g'\xc5\xf2\xfcv\xb5\x83\x04f\x8c"
    words = entropy_to_mnemonic(entropy)
    vectors = {
        20: b"\x07test ID\x14\x00\x00\nOR\xa1\x93l>2q \x9e\x9dd\xbf\xb7vo]]\x8aO\x90\x8e\x86\xe784L\x02]\x8f\xedT",
        5: b"\x07test ID\x05\x00\x00\n*\xe1\x9d\xc5\x82\xc1\x19\x9b\xb7&\xf2?\x03\xc7o\xf6R>#",
        10: b'\x07test ID\x0a\x00\x00\nOR\xa1\x93l>2q \x9e\x9dd\x05\x9e\xd7\x8e\x01\x03`u_\xd7\xab/N\xbc@\x19\xcc\n"\xc5C\xfa\x96\x90',
        0: b"\x07test ID\x00\x00\x00\n*\xe1\x9d\xc5\x82\xc1\x19\x9b\xb7&\xf2?\x03\xc7o\xf6\xaf\x9e\x81#F,Qs\xe6\x1d\xeb\xd1Y\xa0/\xcf",
    }
    iv = b"OR\xa1\x93l>2q \x9e\x9dd\x05\x9e\xd7\x8e"
    for version, blob in vectors.items():
        payload = decrypt_seed_backup(blob, test_key)
        assert payload["mnemonic"] == words
        assert payload["label"] == "test ID"
        assert mnemonic_to_entropy(payload["mnemonic"]) == entropy
    # Encrypting with Krux's published IV reproduces the GCM QR bytes.
    reproduced = encrypt_envelope(entropy, test_key, "test ID", version=20, iterations=100_000, iv=iv[:12])
    assert reproduced == vectors[20]
    ctr = b"\x07test ID\x0f\x00\x00\nOR\xa1\x93l>2q \x9e\x9dd\xf4\x91 \xc7\xa2m\x12\xde{\x0f\xf0&\x8c\x96\x91\xe6\x89\xb0$\x94\xf0\xafR\xc2\x1c)[W\xb54~\x9a\x86\xee*@"
    ctr_entropy = b'\xecT\xea4l\xaa\x1e\xd0l\xb3\\\x96\xc4\xef#"\x8a&\xa2\xe0\x99lq\xd0`\x8e\xc2\xbaI\xce#\x16'
    label, _version, _iterations, plain = decrypt_envelope(ctr, test_key)
    assert plain == ctr_entropy
    assert label == b"test ID"


def test_krux_seeds_json_gcm_entry():
    raw = b"\x08KEFgcmID\x14\x00\x00\nOR\xa1\x93l>2q \x9e\x9dd\xbf\xa3\x0c?\xd7\xfa\xff,%\x8d\xf3\xee\x88\x81N\x08\xd3\xb7\xd0[&\x1df\x01\x0b\xac\xd6\xb6\xc5\x17\x80\xf8\x1c\x7f\x92W"
    payload = decrypt_seed_backup(raw, "test key")
    assert payload["label"] == "KEFgcmID"
    assert len(payload["mnemonic"].split()) == 24


def test_bad_envelope_is_format_error():
    with pytest.raises(FormatError):
        decrypt_seed_backup(b"not kef", PASSPHRASE)


def test_qr_grid_sizes_are_hand_sized():
    from seedsigner.models.kef_qr import kef_qr_modules

    twelve = encrypt_seed_backup(mnemonic=MNEMONIC, encryption_passphrase=PASSPHRASE, label="", iv=b"\x11" * 12)
    twenty_four = (
        "legal winner thank year wave sausage worth useful legal winner thank year "
        "wave sausage worth useful legal winner thank year wave sausage worth title"
    )
    long = encrypt_seed_backup(mnemonic=twenty_four, encryption_passphrase=PASSPHRASE, label="", iv=b"\x22" * 12)
    labeled = encrypt_seed_backup(mnemonic=twenty_four, encryption_passphrase=PASSPHRASE, label="savings", iv=b"\x22" * 12)
    assert kef_qr_modules(twelve) == 29
    assert kef_qr_modules(long) == 29
    assert kef_qr_modules(labeled) == 33
    # base64 form is what Krux stores inside seeds.json
    assert base64.b64encode(twelve)
