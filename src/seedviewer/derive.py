"""BIP32/BIP39/BIP49/BIP84 derivation for Seed Viewer, via buidl.

Addresses are built from the public key. This module does not import embit
and does not offer Taproot.
"""

from __future__ import annotations

import hashlib

from buidl.bech32 import encode_bech32_checksum
from buidl.hd import HDPrivateKey
from buidl.helper import encode_base58_checksum, hash160

from seedsigner.models.bip39_words import WORDLIST_SHA256, load_wordlist


SLIP132 = {
    "ypub": bytes.fromhex("049d7cb2"),
    "zpub": bytes.fromhex("04b24746"),
    "Ypub": bytes.fromhex("0295b43f"),
    "Zpub": bytes.fromhex("02aa7ed3"),
}


def master_key(mnemonic: str, passphrase: str = "") -> HDPrivateKey:
    password = passphrase.encode("utf-8")
    return HDPrivateKey.from_mnemonic(mnemonic, password=password)


def fingerprint(mnemonic: str, passphrase: str = "") -> str:
    return master_key(mnemonic, passphrase).fingerprint().hex()


def _account(mnemonic: str, passphrase: str, path: str) -> HDPrivateKey:
    return master_key(mnemonic, passphrase).traverse(path)


def account_xpubs(mnemonic: str, passphrase: str, path: str, slip_name: str) -> dict:
    node = _account(mnemonic, passphrase, path)
    return {
        "path": path,
        "xpub": node.xpub(),
        "slip": node.xpub(version=SLIP132[slip_name]),
        "slip_name": slip_name,
        "fingerprint": master_key(mnemonic, passphrase).fingerprint().hex(),
    }


def bip84_account(mnemonic: str, passphrase: str = "") -> dict:
    return account_xpubs(mnemonic, passphrase, "m/84h/0h/0h", "zpub")


def bip49_account(mnemonic: str, passphrase: str = "") -> dict:
    return account_xpubs(mnemonic, passphrase, "m/49h/0h/0h", "ypub")


def bip48_account(mnemonic: str, passphrase: str = "", native: bool = True) -> dict:
    if native:
        return account_xpubs(mnemonic, passphrase, "m/48h/0h/0h/2h", "Zpub")
    return account_xpubs(mnemonic, passphrase, "m/48h/0h/0h/1h", "Ypub")


def p2wpkh_address(node: HDPrivateKey) -> str:
    return encode_bech32_checksum(b"\x00\x14" + hash160(node.pub.sec()))


def p2sh_p2wpkh_address(node: HDPrivateKey) -> str:
    redeem = b"\x00\x14" + hash160(node.pub.sec())
    return encode_base58_checksum(b"\x05" + hash160(redeem))


def single_address(mnemonic: str, passphrase: str, kind: str, change: int, index: int) -> str:
    if kind == "bip84":
        path = f"m/84h/0h/0h/{change}/{index}"
        return p2wpkh_address(master_key(mnemonic, passphrase).traverse(path))
    if kind == "bip49":
        path = f"m/49h/0h/0h/{change}/{index}"
        return p2sh_p2wpkh_address(master_key(mnemonic, passphrase).traverse(path))
    raise ValueError("unknown script type")


def child_pubkey(mnemonic: str, passphrase: str, account_path: str, change: int, index: int) -> bytes:
    path = f"{account_path}/{change}/{index}"
    return master_key(mnemonic, passphrase).traverse(path).pub.sec()


def multisig_script(pubkeys: list[bytes], threshold: int) -> bytes:
    keys = sorted(pubkeys)
    if not 1 <= threshold <= len(keys) <= 7:
        raise ValueError("threshold must be between 1 and the number of keys, max 7")
    script = bytes([0x50 + threshold])
    for key in keys:
        if len(key) != 33:
            raise ValueError("multisig keys must be compressed")
        script += bytes([len(key)]) + key
    script += bytes([0x50 + len(keys), 0xAE])
    return script


def multisig_address(pubkeys: list[bytes], threshold: int, native: bool) -> str:
    program = b"\x00\x20" + hashlib.sha256(multisig_script(pubkeys, threshold)).digest()
    if native:
        return encode_bech32_checksum(program)
    return encode_base58_checksum(b"\x05" + hash160(program))


def wordlist_matches_official() -> bool:
    load_wordlist()
    return True


def seedqr_digits(mnemonic: str) -> str:
    """Standard SeedQR: 4 decimal digits per English word index."""
    words = load_wordlist()
    index = {word: position for position, word in enumerate(words)}
    return "".join(f"{index[word]:04d}" for word in mnemonic.split())


# Re-exported so the boot check can name the constant it verified.
OFFICIAL_WORDLIST_SHA256 = WORDLIST_SHA256
