"""Boot self-test. Official vectors; the UI must not start if any fail.

BIP32 vector 1 is from BIP-0032. The abandon/TREZOR seed is from BIP-0039.
The bc1q and 37Vu addresses are the BIP-0084 and BIP-0049 vectors for that seed.
"""

from __future__ import annotations

from buidl.hd import HDPrivateKey

from seedviewer.derive import (
    OFFICIAL_WORDLIST_SHA256,
    bip49_account,
    p2sh_p2wpkh_address,
    p2wpkh_address,
    wordlist_matches_official,
)
from seedsigner.models.bip39_words import WORDLIST_SHA256, entropy_to_mnemonic, mnemonic_to_entropy


ABANDON = (
    "abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon about"
)
# BIP39 empty passphrase and the published "TREZOR" passphrase for this mnemonic.
EMPTY_SEED = bytes.fromhex(
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
)
TREZOR_SEED = bytes.fromhex(
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
    "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
)
BIP32_SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
BIP32_XPUB = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhe"
    "PY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
)
BIP84_ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
BIP49_ADDRESS = "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
BIP84_ZPUB = (
    "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
)


def run_selftest() -> list[str]:
    failures = []

    def check(name: str, ok: bool) -> None:
        if not ok:
            failures.append(name)

    try:
        check("bip39-wordlist", wordlist_matches_official() and WORDLIST_SHA256 == OFFICIAL_WORDLIST_SHA256)
        check("bip39-entropy", entropy_to_mnemonic(mnemonic_to_entropy(ABANDON)) == ABANDON)
        root = HDPrivateKey.from_seed(BIP32_SEED)
        check("bip32-xpub", root.xpub() == BIP32_XPUB)
        check("bip32-fingerprint", root.fingerprint().hex() == "3442193e")
        child = root.traverse("m/0h")
        check(
            "bip32-m/0h",
            child.xpub()
            == "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        )
        from_seed = HDPrivateKey.from_seed(EMPTY_SEED)
        check("bip84-address", p2wpkh_address(from_seed.traverse("m/84h/0h/0h/0/0")) == BIP84_ADDRESS)
        check("bip49-address", p2sh_p2wpkh_address(from_seed.traverse("m/49h/0h/0h/0/0")) == BIP49_ADDRESS)
        from_words = HDPrivateKey.from_mnemonic(ABANDON, password=b"")
        check("bip39-seed", from_words.xpub() == from_seed.xpub())
        trezor = HDPrivateKey.from_mnemonic(ABANDON, password=b"TREZOR")
        check("bip39-trezor", trezor.xpub() == HDPrivateKey.from_seed(TREZOR_SEED).xpub())
        check("bip84-zpub", bip49_account(ABANDON, "")["xpub"].startswith("xpub"))
        account = from_words.traverse("m/84h/0h/0h")
        check("bip84-zpub-value", account.xpub(version=bytes.fromhex("04b24746")) == BIP84_ZPUB)
    except Exception as exc:
        failures.append(f"exception:{exc.__class__.__name__}")
    return failures
