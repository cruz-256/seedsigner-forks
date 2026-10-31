"""BIP39 English mnemonic bytes, checked against the shipped wordlist file.

The SHA-256 below is the official ``bip-0039/english.txt`` file from the
bitcoin/bips repository (2048 lines, each word followed by a newline). Import
refuses to continue if the file on disk does not match.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
_WORDLIST_PATH = Path(__file__).resolve().parents[1] / "resources" / "bip39_english.txt"


def load_wordlist() -> list[str]:
    raw = _WORDLIST_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != WORDLIST_SHA256:
        raise RuntimeError("BIP39 English wordlist SHA-256 does not match the official file")
    words = raw.decode("ascii").splitlines()
    if len(words) != 2048 or any(not word.isascii() or not word.islower() for word in words):
        raise RuntimeError("BIP39 English wordlist is not 2048 lowercase words")
    return words


WORDLIST = load_wordlist()
_INDEX = {word: index for index, word in enumerate(WORDLIST)}


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    words = mnemonic.split()
    if len(words) not in (12, 24):
        raise ValueError("mnemonic must be 12 or 24 English words")
    try:
        indexes = [_INDEX[word] for word in words]
    except KeyError as exc:
        raise ValueError("mnemonic has a word that is not in the English list") from exc
    bits = "".join(f"{index:011b}" for index in indexes)
    checksum_bits = len(words) // 3
    entropy_bits = bits[:-checksum_bits]
    given = bits[-checksum_bits:]
    entropy = int(entropy_bits, 2).to_bytes(len(entropy_bits) // 8, "big")
    digest_bits = "".join(f"{byte:08b}" for byte in hashlib.sha256(entropy).digest())
    if digest_bits[:checksum_bits] != given:
        raise ValueError("mnemonic checksum is wrong")
    return entropy


def entropy_to_mnemonic(entropy: bytes) -> str:
    if len(entropy) not in (16, 32):
        raise ValueError("BIP39 entropy must be 16 or 32 bytes")
    digest_bits = "".join(f"{byte:08b}" for byte in hashlib.sha256(entropy).digest())
    entropy_bits = "".join(f"{byte:08b}" for byte in entropy)
    checksum_bits = len(entropy) * 8 // 32
    bits = entropy_bits + digest_bits[:checksum_bits]
    words = [WORDLIST[int(bits[offset:offset + 11], 2)] for offset in range(0, len(bits), 11)]
    return " ".join(words)
