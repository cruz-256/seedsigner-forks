"""AES-256 primitives and the seed-backup helpers that sit on Krux KEF.

The block cipher and GCM code follow FIPS 197 and NIST SP 800-38D. A
known-answer self-test runs at import. KEF itself lives in ``kef.py``; the
functions at the bottom of this module turn a BIP39 mnemonic into a KEF
envelope and back. This stays on the standard library so
``tools/decrypt_seed_backup.py`` can recover a backup off the device.

KEF does not store a BIP39 passphrase. The envelope plaintext is BIP39 entropy
(16 or 32 bytes). The optional KEF ``id`` is a label, not a secret.
"""

from __future__ import annotations

import hmac
import unicodedata


NONCE_LEN = 12
TAG_LEN = 16

MIN_ENCRYPTION_PASSPHRASE_CHARS = 8
# Krux QR exports use 100_000 PBKDF2-HMAC-SHA256 iterations (stored as 10).
DEFAULT_KEF_ITERATIONS = 100_000
DEFAULT_KEF_VERSION = 20

_GF_POLY = 0x11B


class EncryptedBackupError(Exception):
    """Base error. Messages are safe to show; they never include secret material."""


class FormatError(EncryptedBackupError):
    """The file is not a readable SSENC1 backup."""


class DecryptionError(EncryptedBackupError):
    """Wrong encryption passphrase, or the ciphertext was modified."""


class PayloadError(EncryptedBackupError):
    """The file decrypted, but the JSON payload is not a seed this app can load."""


def normalize_encryption_passphrase(passphrase: str) -> str:
    if not isinstance(passphrase, str):
        raise ValueError("encryption passphrase must be a string")
    if "\x00" in passphrase:
        raise ValueError("encryption passphrase must not contain NUL")
    return unicodedata.normalize("NFKD", passphrase)


def encryption_passphrase_is_acceptable(passphrase: str) -> bool:
    """Device UI floor. This is not a strength guarantee; use a long passphrase."""
    try:
        normalized = normalize_encryption_passphrase(passphrase)
    except ValueError:
        return False
    return len(normalized) >= MIN_ENCRYPTION_PASSPHRASE_CHARS


def _gf_mul(a: int, b: int) -> int:
    """Multiply in AES's GF(2^8), reducing by x^8 + x^4 + x^3 + x + 1."""
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return product


def _gf_inv(value: int) -> int:
    if value == 0:
        return 0
    # a^(2^8 - 2) = a^254 = a^-1 in this field.
    result = 1
    base = value
    exponent = 254
    while exponent:
        if exponent & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exponent >>= 1
    return result


def _rotl8(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def _sbox_byte(value: int) -> int:
    # FIPS 197 section 5.1.1: multiplicative inverse, then the affine transform.
    inverse = _gf_inv(value)
    mixed = inverse
    for shift in (1, 2, 3, 4):
        mixed ^= _rotl8(inverse, shift)
    return mixed ^ 0x63


_SBOX = bytes(_sbox_byte(i) for i in range(256))
if _SBOX[0x00] != 0x63 or _SBOX[0x01] != 0x7C:
    raise RuntimeError("AES S-box generation does not match FIPS 197")


def _rcon_bytes() -> list[int]:
    values = [0x00]
    carry = 0x01
    for _ in range(10):
        values.append(carry)
        carry = _gf_mul(carry, 0x02)
    return values


_RCON = _rcon_bytes()


def _rot_word(word: int) -> int:
    return ((word << 8) & 0xFFFFFFFF) | (word >> 24)


def _sub_word(word: int) -> int:
    return (
        (_SBOX[(word >> 24) & 0xFF] << 24)
        | (_SBOX[(word >> 16) & 0xFF] << 16)
        | (_SBOX[(word >> 8) & 0xFF] << 8)
        | _SBOX[word & 0xFF]
    )


def _expand_key(key: bytes) -> list[bytes]:
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    nk = 8
    nr = 14
    nb = 4
    words = [0] * (nb * (nr + 1))
    for index in range(nk):
        words[index] = int.from_bytes(key[4 * index:4 * index + 4], "big")
    for index in range(nk, nb * (nr + 1)):
        temp = words[index - 1]
        if index % nk == 0:
            temp = _sub_word(_rot_word(temp)) ^ (_RCON[index // nk] << 24)
        elif index % nk == 4:
            temp = _sub_word(temp)
        words[index] = words[index - nk] ^ temp
    round_keys = []
    for round_index in range(nr + 1):
        block = b"".join(
            words[round_index * 4 + column].to_bytes(4, "big")
            for column in range(4)
        )
        round_keys.append(block)
    return round_keys


def _add_round_key(state: bytes, round_key: bytes) -> bytes:
    return bytes(left ^ right for left, right in zip(state, round_key))


def _sub_bytes(state: bytes) -> bytes:
    return bytes(_SBOX[byte] for byte in state)


def _shift_rows(state: bytes) -> bytes:
    # Column-major state: index = row + 4 * column, which is also the input order.
    value = list(state)
    value[1], value[5], value[9], value[13] = value[5], value[9], value[13], value[1]
    value[2], value[6], value[10], value[14] = value[10], value[14], value[2], value[6]
    value[3], value[7], value[11], value[15] = value[15], value[3], value[7], value[11]
    return bytes(value)


def _mix_columns(state: bytes) -> bytes:
    mixed = bytearray(16)
    for column in range(4):
        index = 4 * column
        a0, a1, a2, a3 = state[index:index + 4]
        mixed[index] = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
        mixed[index + 1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
        mixed[index + 2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
        mixed[index + 3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)
    return bytes(mixed)


def aes256_encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    state = _add_round_key(block, round_keys[0])
    for round_index in range(1, 14):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[round_index])
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[14])
    return state


_INV_SBOX = bytearray(256)
for _index, _value in enumerate(_SBOX):
    _INV_SBOX[_value] = _index
_INV_SBOX = bytes(_INV_SBOX)


def _inv_sub_bytes(state: bytes) -> bytes:
    return bytes(_INV_SBOX[byte] for byte in state)


def _inv_shift_rows(state: bytes) -> bytes:
    value = list(state)
    value[1], value[5], value[9], value[13] = value[13], value[1], value[5], value[9]
    value[2], value[6], value[10], value[14] = value[10], value[14], value[2], value[6]
    value[3], value[7], value[11], value[15] = value[7], value[11], value[15], value[3]
    return bytes(value)


def _inv_mix_columns(state: bytes) -> bytes:
    mixed = bytearray(16)
    for column in range(4):
        index = 4 * column
        a0, a1, a2, a3 = state[index:index + 4]
        mixed[index] = _gf_mul(a0, 14) ^ _gf_mul(a1, 11) ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9)
        mixed[index + 1] = _gf_mul(a0, 9) ^ _gf_mul(a1, 14) ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13)
        mixed[index + 2] = _gf_mul(a0, 13) ^ _gf_mul(a1, 9) ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11)
        mixed[index + 3] = _gf_mul(a0, 11) ^ _gf_mul(a1, 13) ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14)
    return bytes(mixed)


def aes256_decrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    state = _add_round_key(block, round_keys[14])
    for round_index in range(13, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[round_index])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])
    return state


def aes256_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    round_keys = _expand_key(key)
    return b"".join(
        aes256_encrypt_block(plaintext[offset:offset + 16], round_keys)
        for offset in range(0, len(plaintext), 16)
    )


def aes256_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    round_keys = _expand_key(key)
    return b"".join(
        aes256_decrypt_block(ciphertext[offset:offset + 16], round_keys)
        for offset in range(0, len(ciphertext), 16)
    )


def aes256_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    round_keys = _expand_key(key)
    previous = iv
    output = bytearray()
    for offset in range(0, len(plaintext), 16):
        block = bytes(left ^ right for left, right in zip(plaintext[offset:offset + 16], previous))
        previous = aes256_encrypt_block(block, round_keys)
        output.extend(previous)
    return bytes(output)


def aes256_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    round_keys = _expand_key(key)
    previous = iv
    output = bytearray()
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset:offset + 16]
        plain = bytes(left ^ right for left, right in zip(aes256_decrypt_block(block, round_keys), previous))
        output.extend(plain)
        previous = block
    return bytes(output)


def aes256_ctr_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """CTR with a 12-byte nonce. The first counter block is nonce || 0x00000000."""
    if len(nonce) != 12:
        raise ValueError("AES-CTR nonce must be 12 bytes")
    return _ctr_xor(data, nonce + b"\x00\x00\x00\x00", _expand_key(key))


def _inc32(block: bytes) -> bytes:
    prefix, counter = block[:12], block[12:]
    value = (int.from_bytes(counter, "big") + 1) & 0xFFFFFFFF
    return prefix + value.to_bytes(4, "big")


def _ghash_mul(x_int: int, y_int: int) -> int:
    # NIST SP 800-38D Algorithm 1. R = 11100001 || 0^120.
    z_int = 0
    v_int = x_int
    reduction = 0xE1000000000000000000000000000000
    for bit in range(128):
        if (y_int >> (127 - bit)) & 1:
            z_int ^= v_int
        if v_int & 1:
            v_int = (v_int >> 1) ^ reduction
        else:
            v_int >>= 1
    return z_int


def _padded_blocks(data: bytes):
    if not data:
        return
    full, remainder = divmod(len(data), 16)
    for index in range(full):
        yield data[index * 16:(index + 1) * 16]
    if remainder:
        yield data[full * 16:] + b"\x00" * (16 - remainder)


def _ghash(hash_subkey: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    h_int = int.from_bytes(hash_subkey, "big")
    y_int = 0
    for block in _padded_blocks(aad):
        y_int = _ghash_mul(y_int ^ int.from_bytes(block, "big"), h_int)
    for block in _padded_blocks(ciphertext):
        y_int = _ghash_mul(y_int ^ int.from_bytes(block, "big"), h_int)
    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    y_int = _ghash_mul(y_int ^ int.from_bytes(lengths, "big"), h_int)
    return y_int.to_bytes(16, "big")


def _ctr_xor(data: bytes, counter: bytes, round_keys: list[bytes]) -> bytes:
    output = bytearray()
    block_counter = counter
    for offset in range(0, len(data), 16):
        keystream = aes256_encrypt_block(block_counter, round_keys)
        chunk = data[offset:offset + 16]
        output.extend(byte ^ key for byte, key in zip(chunk, keystream))
        block_counter = _inc32(block_counter)
    return bytes(output)


def aes256_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    if len(nonce) != NONCE_LEN:
        raise ValueError("AES-GCM nonce must be 12 bytes")
    round_keys = _expand_key(key)
    hash_subkey = aes256_encrypt_block(b"\x00" * 16, round_keys)
    j0 = nonce + b"\x00\x00\x00\x01"
    ciphertext = _ctr_xor(plaintext, _inc32(j0), round_keys)
    tag_mask = aes256_encrypt_block(j0, round_keys)
    tag = bytes(left ^ right for left, right in zip(_ghash(hash_subkey, aad, ciphertext), tag_mask))
    return ciphertext, tag


def aes256_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, tag: bytes) -> bytes:
    if len(tag) != TAG_LEN:
        raise DecryptionError("decryption failed")
    return _gcm_open(key, nonce, ciphertext, aad, tag)


def aes256_gcm_open_truncated(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, tag: bytes) -> bytes | None:
    """Verify a 1-16 byte tag prefix. Returns None on failure, matching KEF's silent miss."""
    if not tag or len(tag) > TAG_LEN:
        return None
    try:
        return _gcm_open(key, nonce, ciphertext, aad, tag)
    except DecryptionError:
        return None


def _gcm_open(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, tag: bytes) -> bytes:
    if len(nonce) != NONCE_LEN:
        raise DecryptionError("decryption failed")
    round_keys = _expand_key(key)
    hash_subkey = aes256_encrypt_block(b"\x00" * 16, round_keys)
    j0 = nonce + b"\x00\x00\x00\x01"
    tag_mask = aes256_encrypt_block(j0, round_keys)
    expected = bytes(left ^ right for left, right in zip(_ghash(hash_subkey, aad, ciphertext), tag_mask))
    plaintext = bytearray(_ctr_xor(ciphertext, _inc32(j0), round_keys))
    if not hmac.compare_digest(expected[:len(tag)], tag):
        for index in range(len(plaintext)):
            plaintext[index] = 0
        raise DecryptionError("decryption failed")
    return bytes(plaintext)


def _known_answer_self_test() -> None:
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    ciphertext = aes256_encrypt_block(plaintext, _expand_key(key))
    if ciphertext != bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"):
        raise RuntimeError("AES-256 known-answer self-test failed")
    if aes256_decrypt_block(ciphertext, _expand_key(key)) != plaintext:
        raise RuntimeError("AES-256 decrypt known-answer self-test failed")
    gcm_ciphertext, gcm_tag = aes256_gcm_encrypt(b"\x00" * 32, b"\x00" * 12, b"", b"")
    if gcm_ciphertext != b"" or gcm_tag != bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b"):
        raise RuntimeError("AES-256-GCM known-answer self-test failed")


_known_answer_self_test()


def encrypt_seed_backup(
    *,
    mnemonic: str,
    encryption_passphrase: str,
    label: str = "",
    iv: bytes | None = None,
    iterations: int = DEFAULT_KEF_ITERATIONS,
    version: int = DEFAULT_KEF_VERSION,
) -> bytes:
    """Return a Krux KEF envelope. ``encryption_passphrase`` is not a BIP39 passphrase.

    The plaintext is BIP39 entropy. ``label`` is the KEF id and is visible
    before decryption. Passphrase bytes are UTF-8 with no Unicode normalization,
    which is what Krux writes.
    """
    from seedsigner.models.bip39_words import mnemonic_to_entropy
    from seedsigner.models.kef import encrypt_envelope

    if not isinstance(encryption_passphrase, str) or encryption_passphrase == "":
        raise ValueError("encryption passphrase is required")
    if "\x00" in encryption_passphrase:
        raise ValueError("encryption passphrase must not contain NUL")
    try:
        entropy = mnemonic_to_entropy(mnemonic)
    except ValueError as exc:
        raise PayloadError("mnemonic is not valid BIP39 English") from exc
    try:
        return encrypt_envelope(
            entropy,
            encryption_passphrase,
            label,
            version=version,
            iterations=iterations,
            iv=iv,
        )
    except ValueError as exc:
        raise PayloadError(str(exc)) from exc


def decrypt_seed_backup(blob: bytes, encryption_passphrase: str) -> dict:
    """Decrypt a KEF envelope and return mnemonic, label, and version.

    Raises FormatError for a blob that is not KEF, and DecryptionError when
    the passphrase is wrong or authentication fails.
    """
    from seedsigner.models.bip39_words import entropy_to_mnemonic
    from seedsigner.models.kef import FormatError as KefFormatError
    from seedsigner.models.kef import decrypt_envelope

    if not isinstance(encryption_passphrase, str) or "\x00" in encryption_passphrase:
        raise DecryptionError("decryption failed")
    try:
        label, version, iterations, entropy = decrypt_envelope(bytes(blob), encryption_passphrase)
    except KefFormatError as exc:
        raise FormatError("backup is not a KEF envelope") from exc
    except ValueError as exc:
        raise DecryptionError("decryption failed") from exc
    if entropy is None:
        raise DecryptionError("decryption failed")
    try:
        mnemonic = entropy_to_mnemonic(entropy)
    except ValueError as exc:
        raise PayloadError("decrypted data is not BIP39 entropy") from exc
    try:
        label_text = label.decode("utf-8")
    except UnicodeError:
        label_text = label.hex()
    return {
        "mnemonic": mnemonic,
        "label": label_text,
        "version": version,
        "iterations": iterations,
        "seed_type": "bip39",
        "include_passphrase": False,
        "passphrase": "",
        "wordlist": "en",
    }


def preview_kef_label(blob: bytes) -> dict:
    """Read the public KEF id and version without decrypting."""
    from seedsigner.models.kef import VERSIONS, unwrap

    try:
        label, version, iterations, _payload = unwrap(bytes(blob))
    except ValueError as exc:
        raise FormatError("backup is not a KEF envelope") from exc
    try:
        label_text = label.decode("utf-8")
    except UnicodeError:
        label_text = label.hex()
    name = VERSIONS.get(version, {}).get("name", str(version))
    return {"label": label_text, "version": version, "version_name": name, "iterations": iterations}
