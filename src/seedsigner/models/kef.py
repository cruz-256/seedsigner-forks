"""Krux Encrypted Format (KEF), CPython port of krux ``kef.py``.

The version table, wrap/unwrap rules, padding, and authentication match
selfcustody/krux (MIT). AES is the implementation in ``encrypted_backup``.
Password and id bytes are UTF-8 with no Unicode normalization.

Encrypting uses version 20 (AES-GCM, 4-byte tag, no padding). Decrypt accepts
every version Krux currently defines. A wrong key returns None from
``Cipher.decrypt``; callers that want an exception use ``decrypt_envelope``.
"""

from __future__ import annotations

import hashlib
import secrets
import zlib

from seedsigner.models.encrypted_backup import (
    aes256_cbc_decrypt,
    aes256_cbc_encrypt,
    aes256_ctr_xor,
    aes256_ecb_decrypt,
    aes256_ecb_encrypt,
    aes256_gcm_encrypt,
    aes256_gcm_open_truncated,
)


MODE_ECB = 1
MODE_CBC = 2
MODE_CTR = 6
MODE_GCM = 7

VERSIONS = {
    0: {"name": "AES-ECB v1", "mode": MODE_ECB, "auth": -16},
    1: {"name": "AES-CBC v1", "mode": MODE_CBC, "auth": -16},
    5: {"name": "AES-ECB", "mode": MODE_ECB, "auth": 3},
    6: {"name": "AES-ECB +p", "mode": MODE_ECB, "pkcs_pad": True, "auth": -4},
    7: {"name": "AES-ECB +c", "mode": MODE_ECB, "pkcs_pad": True, "auth": -4, "compress": True},
    10: {"name": "AES-CBC", "mode": MODE_CBC, "auth": 4},
    11: {"name": "AES-CBC +p", "mode": MODE_CBC, "pkcs_pad": True, "auth": -4},
    12: {"name": "AES-CBC +c", "mode": MODE_CBC, "pkcs_pad": True, "auth": -4, "compress": True},
    15: {"name": "AES-CTR", "mode": MODE_CTR, "pkcs_pad": None, "auth": -4},
    16: {"name": "AES-CTR +c", "mode": MODE_CTR, "pkcs_pad": None, "auth": -4, "compress": True},
    20: {"name": "AES-GCM", "mode": MODE_GCM, "pkcs_pad": None, "auth": 4},
    21: {"name": "AES-GCM +c", "mode": MODE_GCM, "pkcs_pad": None, "auth": 4, "compress": True},
}
MODE_NUMBERS = {
    "AES-ECB": MODE_ECB,
    "AES-CBC": MODE_CBC,
    "AES-CTR": MODE_CTR,
    "AES-GCM": MODE_GCM,
}
MODE_IVS = {MODE_CBC: 16, MODE_CTR: 12, MODE_GCM: 12}
AES_BLOCK_SIZE = 16
MIN_ITERATIONS = 10_000
_MAX_PLAINTEXT = 64 * 1024
_MAX_ENVELOPE = 96 * 1024


class FormatError(ValueError):
    """The bytes are not a KEF envelope this build can parse."""


def _as_bytes(value: bytes | str, label: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"{label} is not bytes or str")


def _pad(some_bytes: bytes, pkcs_pad) -> bytes:
    if pkcs_pad is None:
        return some_bytes
    if not isinstance(some_bytes, bytes):
        raise TypeError("pkcs_pad is not (None, True, False)")
    length = (AES_BLOCK_SIZE - len(some_bytes) % AES_BLOCK_SIZE) % AES_BLOCK_SIZE
    if pkcs_pad is True:
        if length == 0:
            length = AES_BLOCK_SIZE
        return some_bytes + bytes([length]) * length
    if pkcs_pad is False:
        return some_bytes + b"\x00" * length
    raise TypeError("pkcs_pad is not (None, True, False)")


def _unpad(some_bytes: bytes, pkcs_pad) -> bytes:
    if pkcs_pad is None:
        return some_bytes
    if pkcs_pad is True:
        length = some_bytes[-1]
        if length == 0 or length > AES_BLOCK_SIZE or some_bytes[-length:] != bytes([length]) * length:
            raise ValueError("bad pkcs padding")
        return some_bytes[:-length]
    if pkcs_pad is False:
        return some_bytes.rstrip(b"\x00")
    raise TypeError("pkcs_pad is not in (None, True, False)")


def _deflate(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise ValueError("Error compressing")
    return zlib.compress(data, level=6, wbits=-10)


def _reinflate(data: bytes) -> bytes:
    try:
        inflated = zlib.decompress(data, wbits=-10)
    except zlib.error as exc:
        raise ValueError("Error decompressing") from exc
    if len(inflated) > _MAX_PLAINTEXT:
        raise ValueError("exceeds size limit")
    return inflated


class Cipher:
    def __init__(self, key: bytes | str, salt: bytes | str, iterations: int):
        if not isinstance(iterations, int) or isinstance(iterations, bool) or iterations < 1:
            raise ValueError("Invalid iterations")
        key_bytes = _as_bytes(key, "key")
        salt_bytes = _as_bytes(salt, "salt")
        self._key = hashlib.pbkdf2_hmac("sha256", key_bytes, salt_bytes, iterations, dklen=32)

    def encrypt(self, plain: bytes, version: int, iv: bytes = b"", fail_unsafe: bool = True) -> bytes:
        spec = VERSIONS[version]
        mode = spec["mode"]
        v_iv = MODE_IVS.get(mode, 0)
        v_pkcs_pad = spec.get("pkcs_pad", False)
        v_auth = spec.get("auth", 0)
        v_compress = spec.get("compress", False)
        auth = b""
        if iv is None:
            iv = b""
        if not isinstance(plain, bytes):
            raise TypeError("Plaintext is not bytes")
        if len(plain) > _MAX_PLAINTEXT:
            raise ValueError("Plaintext is too large")
        if v_compress:
            plain = _deflate(plain)
        if fail_unsafe and v_pkcs_pad is False and v_auth > 0 and plain[-1:] == b"\x00":
            raise ValueError("Cannot validate decryption for this plaintext")
        if v_auth != 0 and mode in (MODE_ECB, MODE_CBC, MODE_CTR):
            if v_auth > 0:
                auth = hashlib.sha256(bytes([version]) + iv + plain + self._key).digest()[:v_auth]
            else:
                auth = hashlib.sha256(plain).digest()[:-v_auth]
                if fail_unsafe and v_pkcs_pad is False and auth[-1:] == b"\x00":
                    raise ValueError("Cannot validate decryption for this plaintext")
                plain += auth
                auth = b""
        if v_pkcs_pad is True or v_pkcs_pad is False:
            plain = _pad(plain, pkcs_pad=v_pkcs_pad)
        if fail_unsafe and mode == MODE_ECB:
            blocks = [plain[offset:offset + 16] for offset in range(0, len(plain), 16)]
            if len(set(blocks)) != len(blocks):
                raise ValueError("Duplicate blocks in ECB mode")
        if v_iv > 0:
            if not (isinstance(iv, bytes) and len(iv) == v_iv):
                raise ValueError("Wrong IV length")
        elif iv:
            raise ValueError("IV is not required")
        if mode == MODE_ECB:
            encrypted = aes256_ecb_encrypt(self._key, plain)
        elif mode == MODE_CBC:
            encrypted = aes256_cbc_encrypt(self._key, iv, plain)
        elif mode == MODE_CTR:
            encrypted = aes256_ctr_xor(self._key, iv, plain)
        elif mode == MODE_GCM:
            ciphertext, tag = aes256_gcm_encrypt(self._key, iv, plain, b"")
            encrypted = ciphertext
            auth = tag[:v_auth]
        else:
            raise ValueError("Invalid version")
        return iv + encrypted + auth

    def decrypt(self, payload: bytes, version: int):
        spec = VERSIONS[version]
        mode = spec["mode"]
        v_iv = MODE_IVS.get(mode, 0)
        v_pkcs_pad = spec.get("pkcs_pad", False)
        v_auth = spec.get("auth", 0)
        v_compress = spec.get("compress", False)
        minimum = 1 if mode in (MODE_CTR, MODE_GCM) else AES_BLOCK_SIZE
        minimum += min(0, v_auth) + v_iv
        if len(payload) <= minimum:
            raise ValueError("Invalid Payload")
        if not v_iv:
            iv = b""
        else:
            iv = payload[:v_iv]
            payload = payload[v_iv:]
        auth = None
        if v_auth > 0:
            auth = payload[-v_auth:]
            payload = payload[:-v_auth]
        if mode == MODE_ECB:
            decrypted = aes256_ecb_decrypt(self._key, payload)
        elif mode == MODE_CBC:
            decrypted = aes256_cbc_decrypt(self._key, iv, payload)
        elif mode == MODE_CTR:
            decrypted = aes256_ctr_xor(self._key, iv, payload)
        elif mode == MODE_GCM:
            opened = aes256_gcm_open_truncated(self._key, iv, payload, b"", auth or b"")
            decrypted = opened
        else:
            raise ValueError("Invalid version")
        if v_auth != 0 and mode != MODE_GCM:
            try:
                decrypted = self._authenticate(version, iv, decrypted, auth, mode, v_auth, v_pkcs_pad)
            except Exception:
                decrypted = None
        elif mode == MODE_GCM and decrypted is None:
            return None
        if decrypted and v_compress:
            try:
                decrypted = _reinflate(decrypted)
            except ValueError:
                return None
        return decrypted

    def _authenticate(self, version, iv, decrypted, auth, mode, v_auth, v_pkcs_pad):
        length_before = len(decrypted)
        if v_pkcs_pad in (False, True):
            decrypted = _unpad(decrypted, pkcs_pad=v_pkcs_pad)
        if v_auth < 0:
            auth = decrypted[v_auth:]
            decrypted = decrypted[:v_auth]
        attempts = 1
        if v_pkcs_pad is False:
            attempts = min(length_before - len(decrypted), abs(v_auth) + 1) + 1
        for _ in range(attempts):
            if v_auth > 0:
                checksum = hashlib.sha256(bytes([version]) + iv + decrypted + self._key).digest()[:v_auth]
            else:
                checksum = hashlib.sha256(decrypted).digest()[:-v_auth]
            if checksum == auth:
                return decrypted
            if v_auth < 0:
                decrypted += auth[:1]
                auth = auth[1:] + b"\x00"
            else:
                decrypted += b"\x00"
        return None


def wrap(id_: bytes | str, version: int, iterations: int, payload: bytes) -> bytes:
    try:
        id_bytes = id_ if isinstance(id_, bytes) else id_.encode("utf-8")
        if not 0 <= len(id_bytes) <= 252:
            raise ValueError
    except Exception as exc:
        raise ValueError("Invalid ID") from exc
    spec = VERSIONS.get(version)
    if spec is None or spec.get("mode") is None:
        raise ValueError("Invalid version")
    if not isinstance(iterations, int) or isinstance(iterations, bool):
        raise ValueError("Invalid iterations")
    stored = iterations
    if iterations % 10000 == 0:
        stored = iterations // 10000
        if not 1 <= stored <= 10000:
            raise ValueError("Invalid iterations")
    elif not 10000 < iterations < 2**24:
        raise ValueError("Invalid iterations")
    extra = MODE_IVS.get(spec["mode"], 0)
    if spec.get("auth", 0) > 0:
        extra += spec["auth"]
    if not isinstance(payload, bytes):
        raise ValueError("Payload is not bytes")
    if spec.get("pkcs_pad", False) in (True, False):
        if (len(payload) - extra) % 16 != 0:
            raise ValueError("Ciphertext is not aligned")
        if (len(payload) - extra) // 16 < 1:
            raise ValueError("Ciphertext is too short")
    return b"".join([
        bytes([len(id_bytes)]),
        id_bytes,
        bytes([version]),
        stored.to_bytes(3, "big"),
        payload,
    ])


def unwrap(kef_bytes: bytes):
    if not isinstance(kef_bytes, (bytes, bytearray)) or len(kef_bytes) < 5 or len(kef_bytes) > _MAX_ENVELOPE:
        raise ValueError("Invalid format")
    kef_bytes = bytes(kef_bytes)
    length = kef_bytes[0]
    try:
        version = kef_bytes[1 + length]
        spec = VERSIONS.get(version)
        if spec is None or spec.get("mode") is None:
            raise ValueError
    except Exception as exc:
        raise FormatError("Invalid format") from exc
    id_ = kef_bytes[1:1 + length]
    stored = int.from_bytes(kef_bytes[2 + length:5 + length], "big")
    iterations = stored * 10000 if stored <= 10000 else stored
    if iterations < MIN_ITERATIONS:
        raise ValueError("Invalid iterations")
    payload = kef_bytes[length + 5:]
    extra = MODE_IVS.get(spec["mode"], 0)
    if spec.get("auth", 0) > 0:
        extra += spec["auth"]
    if spec.get("pkcs_pad", False) in (True, False):
        if (len(payload) - extra) % 16 != 0:
            raise ValueError("Ciphertext is not aligned")
        if (len(payload) - extra) // 16 < 1:
            raise ValueError("Ciphertext is too short")
    return (id_, version, iterations, payload)


def looks_like_envelope(data: bytes) -> bool:
    try:
        unwrap(data)
    except Exception:
        return False
    return True


def encrypt_envelope(
    plaintext: bytes,
    password: bytes | str,
    label: bytes | str = b"",
    *,
    version: int = 20,
    iterations: int = 100_000,
    iv: bytes | None = None,
) -> bytes:
    spec = VERSIONS.get(version)
    if spec is None or spec.get("mode") is None:
        raise ValueError("Invalid version")
    iv_len = MODE_IVS.get(spec["mode"], 0)
    if iv is None:
        iv = secrets.token_bytes(iv_len) if iv_len else b""
    cipher = Cipher(password, label, iterations)
    payload = cipher.encrypt(plaintext, version, iv)
    return wrap(label, version, iterations, payload)


def decrypt_envelope(envelope: bytes, password: bytes | str):
    """Return (label, version, iterations, plaintext). Plaintext is None on a bad key."""
    label, version, iterations, payload = unwrap(envelope)
    cipher = Cipher(password, label, iterations)
    return label, version, iterations, cipher.decrypt(payload, version)
