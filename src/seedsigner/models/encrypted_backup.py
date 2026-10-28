"""Encrypted seed backup file format (SSENC1).

This module is intentionally stdlib-only so ``tools/decrypt_seed_backup.py`` can
recover a backup on another computer without installing SeedSigner.

File layout, big-endian, version 1
-----------------------------------
Offset  Size  Field
0       6     Magic ASCII ``SSENC1``
6       1     Version (``1``)
7       1     KDF id (``1`` = scrypt)
8       1     Cipher id (``1`` = AES-256-GCM)
9       1     Flags (must be ``0``)
10      4     scrypt N
14      4     scrypt r
18      4     scrypt p
22      16    scrypt salt
38      12    AES-GCM nonce
50      var   ciphertext
end-16  16    GCM authentication tag

The 50-byte header is AES-GCM additional authenticated data, so a flipped
length or KDF parameter fails authentication.

The plaintext is compact UTF-8 JSON:

    {"format":"seedsigner-encrypted-backup","include_passphrase":false,
     "mnemonic":"word1 word2 ...","seed_type":"bip39","version":1,"wordlist":"en"}

``passphrase`` is present only when ``include_passphrase`` is true. That value
is the BIP-39 passphrase or Electrum extension, not the encryption passphrase.

Encryption passphrase bytes are Unicode NFKD, then UTF-8. Letter case matters.
scrypt parameters used by this device are N=2**15, r=8, p=4 (about 32 MiB).
They are stored in the header; decryption uses the header, not these defaults.
N=2**18 would match age's default work factor but needs ~256 MiB, which is too
much for a Raspberry Pi Zero next to the rest of the app.

The AES-256 and GCM code below follows FIPS 197 and NIST SP 800-38D. A
known-answer self-test runs at import. This is not a general-purpose crypto
library; do not reuse it for other protocols.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import struct
import unicodedata


MAGIC = b"SSENC1"
FORMAT_NAME = "seedsigner-encrypted-backup"
FILE_VERSION = 1
KDF_SCRYPT = 1
CIPHER_AES_256_GCM = 1
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
HEADER = struct.Struct(">6sBBBBIII16s12s")
assert HEADER.size == 50

# Pi Zero has 512 MiB, and the app already holds camera and UI buffers.
# 128 * r * N = 32 MiB at these settings. p=4 buys extra CPU time without
# raising that memory ceiling. Import refuses parameters above the cap below
# so a hostile file cannot ask the device to allocate a huge scrypt buffer.
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 4
SCRYPT_DKLEN = 32
_MAX_SCRYPT_MEMORY = 48 * 1024 * 1024
_MAX_SCRYPT_N = 1 << 16
_MAX_SCRYPT_R = 32
_MAX_SCRYPT_P = 16

MIN_ENCRYPTION_PASSPHRASE_CHARS = 8
_MAX_MNEMONIC_CHARS = 512
_MAX_PASSPHRASE_CHARS = 1024
_MAX_PLAINTEXT = 256 * 1024
_MAX_FILE_BYTES = HEADER.size + _MAX_PLAINTEXT + TAG_LEN

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
    round_keys = _expand_key(key)
    hash_subkey = aes256_encrypt_block(b"\x00" * 16, round_keys)
    j0 = nonce + b"\x00\x00\x00\x01"
    tag_mask = aes256_encrypt_block(j0, round_keys)
    expected = bytes(left ^ right for left, right in zip(_ghash(hash_subkey, aad, ciphertext), tag_mask))
    plaintext = bytearray(_ctr_xor(ciphertext, _inc32(j0), round_keys))
    if not hmac.compare_digest(expected, tag):
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
    gcm_ciphertext, gcm_tag = aes256_gcm_encrypt(b"\x00" * 32, b"\x00" * 12, b"", b"")
    if gcm_ciphertext != b"" or gcm_tag != bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b"):
        raise RuntimeError("AES-256-GCM known-answer self-test failed")


_known_answer_self_test()


def _check_scrypt_params(n_cost: int, r_cost: int, p_cost: int) -> None:
    if n_cost < 2 or n_cost & (n_cost - 1) or n_cost > _MAX_SCRYPT_N:
        raise FormatError("rejected scrypt parameters")
    if not (1 <= r_cost <= _MAX_SCRYPT_R) or not (1 <= p_cost <= _MAX_SCRYPT_P):
        raise FormatError("rejected scrypt parameters")
    if 128 * r_cost * n_cost > _MAX_SCRYPT_MEMORY:
        raise FormatError("rejected scrypt parameters")


def _derive_key(passphrase: str, salt: bytes, n_cost: int, r_cost: int, p_cost: int) -> bytes:
    _check_scrypt_params(n_cost, r_cost, p_cost)
    password = normalize_encryption_passphrase(passphrase).encode("utf-8")
    # OpenSSL's default scrypt maxmem is 32 MiB, which is the raw buffer size
    # of the parameters above and gets rejected once allocator overhead is
    # counted. 64 MiB covers the 48 MiB cap enforced in _check_scrypt_params.
    return hashlib.scrypt(
        password,
        salt=salt,
        n=n_cost,
        r=r_cost,
        p=p_cost,
        dklen=SCRYPT_DKLEN,
        maxmem=64 * 1024 * 1024,
    )


def _validate_stored_text(value: str, *, max_chars: int, label: str) -> str:
    if not isinstance(value, str):
        raise PayloadError(f"{label} is missing")
    if len(value) > max_chars or "\x00" in value or "\n" in value or "\r" in value:
        raise PayloadError(f"{label} is not usable")
    return value


def build_payload(
    *,
    mnemonic: str,
    seed_type: str,
    seed_passphrase: str,
    include_seed_passphrase: bool,
) -> bytes:
    if seed_type not in ("bip39", "electrum"):
        raise PayloadError("unsupported seed type")
    mnemonic = _validate_stored_text(mnemonic, max_chars=_MAX_MNEMONIC_CHARS, label="mnemonic")
    if not mnemonic.strip():
        raise PayloadError("mnemonic is missing")
    payload = {
        "format": FORMAT_NAME,
        "include_passphrase": bool(include_seed_passphrase),
        "mnemonic": mnemonic,
        "seed_type": seed_type,
        "version": FILE_VERSION,
        "wordlist": "en",
    }
    if include_seed_passphrase:
        payload["passphrase"] = _validate_stored_text(
            seed_passphrase,
            max_chars=_MAX_PASSPHRASE_CHARS,
            label="passphrase",
        )
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def parse_payload(plaintext: bytes) -> dict:
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PayloadError("payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise PayloadError("payload is not valid JSON")
    if payload.get("format") != FORMAT_NAME or payload.get("version") != FILE_VERSION:
        raise PayloadError("unsupported backup payload")
    if payload.get("wordlist") not in (None, "en"):
        raise PayloadError("only the English wordlist is supported")
    seed_type = payload.get("seed_type")
    if seed_type not in ("bip39", "electrum"):
        raise PayloadError("unsupported seed type")
    mnemonic = _validate_stored_text(payload.get("mnemonic"), max_chars=_MAX_MNEMONIC_CHARS, label="mnemonic")
    include = payload.get("include_passphrase")
    if not isinstance(include, bool):
        raise PayloadError("include_passphrase is missing")
    parsed = {
        "format": FORMAT_NAME,
        "version": FILE_VERSION,
        "seed_type": seed_type,
        "mnemonic": mnemonic,
        "include_passphrase": include,
        "wordlist": "en",
    }
    if include:
        if "passphrase" not in payload:
            raise PayloadError("passphrase is missing")
        parsed["passphrase"] = _validate_stored_text(
            payload.get("passphrase"),
            max_chars=_MAX_PASSPHRASE_CHARS,
            label="passphrase",
        )
    else:
        parsed["passphrase"] = ""
    return parsed


def encrypt_seed_backup(
    *,
    mnemonic: str,
    seed_type: str,
    seed_passphrase: str,
    include_seed_passphrase: bool,
    encryption_passphrase: str,
    salt: bytes | None = None,
    nonce: bytes | None = None,
    scrypt_n: int = SCRYPT_N,
    scrypt_r: int = SCRYPT_R,
    scrypt_p: int = SCRYPT_P,
) -> bytes:
    """Return a complete SSENC1 file. ``encryption_passphrase`` is not the seed passphrase."""
    if not normalize_encryption_passphrase(encryption_passphrase):
        raise ValueError("encryption passphrase is required")
    plaintext = build_payload(
        mnemonic=mnemonic,
        seed_type=seed_type,
        seed_passphrase=seed_passphrase,
        include_seed_passphrase=include_seed_passphrase,
    )
    if len(plaintext) > _MAX_PLAINTEXT:
        raise PayloadError("payload is too large")
    if salt is None:
        salt = secrets.token_bytes(SALT_LEN)
    if nonce is None:
        nonce = secrets.token_bytes(NONCE_LEN)
    if len(salt) != SALT_LEN or len(nonce) != NONCE_LEN:
        raise ValueError("salt must be 16 bytes and nonce must be 12 bytes")
    _check_scrypt_params(scrypt_n, scrypt_r, scrypt_p)
    header = HEADER.pack(
        MAGIC,
        FILE_VERSION,
        KDF_SCRYPT,
        CIPHER_AES_256_GCM,
        0,
        scrypt_n,
        scrypt_r,
        scrypt_p,
        salt,
        nonce,
    )
    key = _derive_key(encryption_passphrase, salt, scrypt_n, scrypt_r, scrypt_p)
    ciphertext, tag = aes256_gcm_encrypt(key, nonce, plaintext, header)
    return header + ciphertext + tag


def decrypt_seed_backup(blob: bytes, encryption_passphrase: str) -> dict:
    """Decrypt ``blob`` and return the payload dict. Raises on any failure."""
    if not isinstance(blob, (bytes, bytearray)):
        raise FormatError("backup is not a byte string")
    blob = bytes(blob)
    if len(blob) < HEADER.size + TAG_LEN or len(blob) > _MAX_FILE_BYTES:
        raise FormatError("backup file size is not valid")
    header = blob[:HEADER.size]
    try:
        magic, version, kdf_id, cipher_id, flags, n_cost, r_cost, p_cost, salt, nonce = HEADER.unpack(header)
    except struct.error as exc:
        raise FormatError("backup header is truncated") from exc
    if magic != MAGIC or version != FILE_VERSION or kdf_id != KDF_SCRYPT or cipher_id != CIPHER_AES_256_GCM or flags != 0:
        raise FormatError("backup header is not SSENC1")
    try:
        if not normalize_encryption_passphrase(encryption_passphrase):
            raise DecryptionError("decryption failed")
    except ValueError as exc:
        raise DecryptionError("decryption failed") from exc
    body = blob[HEADER.size:]
    ciphertext, tag = body[:-TAG_LEN], body[-TAG_LEN:]
    try:
        key = _derive_key(encryption_passphrase, salt, n_cost, r_cost, p_cost)
        plaintext = aes256_gcm_decrypt(key, nonce, ciphertext, header, tag)
    except DecryptionError:
        raise
    except FormatError:
        raise
    except Exception as exc:
        # scrypt and JSON failures should not surface internal details.
        raise DecryptionError("decryption failed") from exc
    return parse_payload(plaintext)
