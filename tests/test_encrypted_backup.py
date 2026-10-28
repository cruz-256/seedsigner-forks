import hashlib
import subprocess
import sys

import pytest

from seedsigner.models.backup_seed import load_seed_from_payload
from seedsigner.models.encrypted_backup import (
    HEADER,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
    DecryptionError,
    FormatError,
    PayloadError,
    aes256_encrypt_block,
    aes256_gcm_encrypt,
    decrypt_seed_backup,
    encrypt_seed_backup,
    encryption_passphrase_is_acceptable,
    _expand_key,
)
from seedsigner.models.seed import ElectrumSeed, Seed


MNEMONIC = "obscure bone gas open exotic abuse virus bunker shuffle nasty ship dash"
ELECTRUM = "regular reject rare profit once math fringe chase until ketchup century escape"
FAST = dict(scrypt_n=1 << 4, scrypt_r=1, scrypt_p=1)


def test_aes256_block_known_answer():
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    ciphertext = aes256_encrypt_block(plaintext, _expand_key(key))
    assert ciphertext == bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")


def test_aes_gcm_known_answers():
    ciphertext, tag = aes256_gcm_encrypt(b"\x00" * 32, b"\x00" * 12, b"", b"")
    assert ciphertext == b""
    assert tag == bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b")

    ciphertext, tag = aes256_gcm_encrypt(
        b"\x00" * 32,
        b"\x00" * 12,
        b"seed signer",
        b"SSENC1hdr",
    )
    assert ciphertext == bytes.fromhex("bdc225596d130209692bb7")
    assert tag == bytes.fromhex("ecb4f01ecceded73447076ee6c3e2fc0")


def test_gcm_matches_cryptography_when_installed():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = bytes(range(32))
    nonce = bytes(range(12))
    aad = b"header-bytes"
    plaintext = b"mnemonic words go here"
    ciphertext, tag = aes256_gcm_encrypt(key, nonce, plaintext, aad)
    assert AESGCM(key).decrypt(nonce, ciphertext + tag, aad) == plaintext


def test_round_trip_mnemonic_only():
    blob = encrypt_seed_backup(
        mnemonic=MNEMONIC,
        seed_type="bip39",
        seed_passphrase="should-not-be-stored",
        include_seed_passphrase=False,
        encryption_passphrase="correct horse battery",
        **FAST,
    )
    payload = decrypt_seed_backup(blob, "correct horse battery")
    assert payload["mnemonic"] == MNEMONIC
    assert payload["include_passphrase"] is False
    assert payload["passphrase"] == ""
    assert payload["seed_type"] == "bip39"
    seed = load_seed_from_payload(payload)
    assert isinstance(seed, Seed)
    assert not isinstance(seed, ElectrumSeed)
    assert seed.mnemonic_str == MNEMONIC
    assert seed.passphrase == ""


def test_round_trip_includes_seed_passphrase_and_electrum():
    blob = encrypt_seed_backup(
        mnemonic=ELECTRUM,
        seed_type="electrum",
        seed_passphrase="Extension",
        include_seed_passphrase=True,
        encryption_passphrase="another-secret-passphrase",
        **FAST,
    )
    payload = decrypt_seed_backup(blob, "another-secret-passphrase")
    assert payload["include_passphrase"] is True
    assert payload["passphrase"] == "Extension"
    seed = load_seed_from_payload(payload)
    assert isinstance(seed, ElectrumSeed)
    assert seed.passphrase == "extension"


def test_passphrase_is_nfkd_and_case_sensitive():
    composed = "caf\u00e9-passphrase"
    decomposed = "cafe\u0301-passphrase"
    blob = encrypt_seed_backup(
        mnemonic=MNEMONIC,
        seed_type="bip39",
        seed_passphrase="",
        include_seed_passphrase=False,
        encryption_passphrase=composed,
        **FAST,
    )
    payload = decrypt_seed_backup(blob, decomposed)
    assert payload["mnemonic"] == MNEMONIC
    with pytest.raises(DecryptionError):
        decrypt_seed_backup(blob, "Caf\u00e9-passphrase")


def test_wrong_passphrase_and_tampering_fail_closed():
    blob = encrypt_seed_backup(
        mnemonic=MNEMONIC,
        seed_type="bip39",
        seed_passphrase="hidden",
        include_seed_passphrase=True,
        encryption_passphrase="right-passphrase",
        salt=b"\x11" * 16,
        nonce=b"\x22" * 12,
        **FAST,
    )
    with pytest.raises(DecryptionError):
        decrypt_seed_backup(blob, "wrong-passphrase")
    flipped = bytearray(blob)
    flipped[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt_seed_backup(bytes(flipped), "right-passphrase")
    # Salt is inside the authenticated header. Changing it must not return a seed.
    salt_flip = bytearray(blob)
    salt_flip[22] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt_seed_backup(bytes(salt_flip), "right-passphrase")
    flag_flip = bytearray(blob)
    flag_flip[9] ^= 0x01
    with pytest.raises(FormatError):
        decrypt_seed_backup(bytes(flag_flip), "right-passphrase")
    with pytest.raises(DecryptionError):
        decrypt_seed_backup(blob, "")


def test_hostile_scrypt_parameters_are_rejected_before_kdf():
    calls = {"n": 0}
    real = hashlib.scrypt

    def counting_scrypt(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    blob = bytearray(encrypt_seed_backup(
        mnemonic=MNEMONIC,
        seed_type="bip39",
        seed_passphrase="",
        include_seed_passphrase=False,
        encryption_passphrase="right-passphrase",
        salt=b"\x33" * 16,
        nonce=b"\x44" * 12,
        **FAST,
    ))
    # N is the uint32 at offset 10. 2**20 is above the cap and must not run.
    blob[10:14] = (1 << 20).to_bytes(4, "big")
    hashlib.scrypt = counting_scrypt
    try:
        with pytest.raises(FormatError):
            decrypt_seed_backup(bytes(blob), "right-passphrase")
    finally:
        hashlib.scrypt = real
    assert calls["n"] == 0
    assert HEADER.size == 50


def test_default_kdf_constants_and_one_production_round_trip():
    assert (SCRYPT_N, SCRYPT_R, SCRYPT_P) == (1 << 15, 8, 4)
    blob = encrypt_seed_backup(
        mnemonic=MNEMONIC,
        seed_type="bip39",
        seed_passphrase="satoshi",
        include_seed_passphrase=True,
        encryption_passphrase="production-passphrase",
    )
    assert int.from_bytes(blob[10:14], "big") == SCRYPT_N
    assert int.from_bytes(blob[14:18], "big") == SCRYPT_R
    assert int.from_bytes(blob[18:22], "big") == SCRYPT_P
    payload = decrypt_seed_backup(blob, "production-passphrase")
    seed = load_seed_from_payload(payload)
    assert seed.passphrase == "satoshi"
    assert seed.mnemonic_str == MNEMONIC


def test_passphrase_floor_and_bad_payloads():
    assert encryption_passphrase_is_acceptable("1234567") is False
    assert encryption_passphrase_is_acceptable("12345678") is True
    with pytest.raises(PayloadError):
        encrypt_seed_backup(
            mnemonic="has\nnewline",
            seed_type="bip39",
            seed_passphrase="",
            include_seed_passphrase=False,
            encryption_passphrase="12345678",
            **FAST,
        )
    with pytest.raises(ValueError):
        encrypt_seed_backup(
            mnemonic=MNEMONIC,
            seed_type="bip39",
            seed_passphrase="",
            include_seed_passphrase=False,
            encryption_passphrase="",
            **FAST,
        )


def test_garbage_is_not_a_backup():
    with pytest.raises(FormatError):
        decrypt_seed_backup(b"not-a-backup", "12345678")


def test_standalone_decrypt_script(tmp_path):
    blob = encrypt_seed_backup(
        mnemonic=MNEMONIC,
        seed_type="bip39",
        seed_passphrase="hidden words",
        include_seed_passphrase=True,
        encryption_passphrase="script-passphrase",
        **FAST,
    )
    path = tmp_path / "backup.ssenc"
    path.write_bytes(blob)
    script = "tools/decrypt_seed_backup.py"
    wrong = subprocess.run(
        [sys.executable, script, str(path)],
        input=b"not-the-passphrase\n",
        capture_output=True,
    )
    assert wrong.returncode == 2
    assert b"obscure bone" not in wrong.stdout
    assert b"hidden words" not in wrong.stdout
    right = subprocess.run(
        [sys.executable, script, str(path)],
        input=b"script-passphrase\n",
        capture_output=True,
    )
    assert right.returncode == 0, right.stderr
    assert b"mnemonic: " + MNEMONIC.encode() in right.stdout
    assert b"passphrase: hidden words" in right.stdout
    assert b"include_passphrase: yes" in right.stdout
