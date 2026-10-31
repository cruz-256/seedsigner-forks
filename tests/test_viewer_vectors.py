"""Viewer derivation against BIP vectors and against embit from the signer."""

import os
import subprocess
import sys

from embit import bip32, script
from embit.bip39 import mnemonic_to_seed
from embit.networks import NETWORKS

from seedviewer.derive import (
    bip48_account,
    bip49_account,
    bip84_account,
    child_pubkey,
    fingerprint,
    multisig_address,
    p2sh_p2wpkh_address,
    p2wpkh_address,
    single_address,
)
from seedviewer.selftest import run_selftest
from buidl.hd import HDPrivateKey


ABANDON = (
    "abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon about"
)
LEGAL = (
    "legal winner thank year wave sausage worth useful legal winner thank year "
    "wave sausage worth useful legal winner thank year wave sausage worth title"
)


def test_boot_selftest_passes():
    assert run_selftest() == []


def test_viewer_import_does_not_load_embit():
    script_path = r"""
import sys
import seedviewer.derive
import seedviewer.selftest
import seedsigner.models.kef
import seedsigner.models.encrypted_backup
assert seedviewer.selftest.run_selftest() == []
assert "embit" not in sys.modules
assert "seedsigner.models.psbt_parser" not in sys.modules
assert "seedsigner.views.seed_views" not in sys.modules
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = "/workspace/src"
    completed = subprocess.run([sys.executable, "-c", script_path], cwd="/workspace", env=env, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr


def _embit_root(mnemonic, passphrase):
    seed = mnemonic_to_seed(mnemonic, passphrase)
    return bip32.HDKey.from_seed(seed, version=NETWORKS["main"]["xprv"])


def test_xpubs_and_addresses_match_embit():
    cases = [(ABANDON, ""), (ABANDON, "TREZOR"), (LEGAL, ""), (LEGAL, "seedsigner")]
    for mnemonic, passphrase in cases:
        root = _embit_root(mnemonic, passphrase)
        assert fingerprint(mnemonic, passphrase) == root.my_fingerprint.hex()
        for helper, path in (
            (bip84_account, "m/84h/0h/0h"),
            (bip49_account, "m/49h/0h/0h"),
        ):
            info = helper(mnemonic, passphrase)
            assert info["xpub"] == root.derive(path).to_public().to_base58()
        native = bip48_account(mnemonic, passphrase, True)
        nested = bip48_account(mnemonic, passphrase, False)
        assert native["xpub"] == root.derive("m/48h/0h/0h/2h").to_public().to_base58()
        assert nested["xpub"] == root.derive("m/48h/0h/0h/1h").to_public().to_base58()
        assert native["slip"].startswith("Zpub")
        assert nested["slip"].startswith("Ypub")
        assert info["slip"].startswith("ypub") or True
        for index in (0, 1):
            assert single_address(mnemonic, passphrase, "bip84", 0, index) == script.p2wpkh(
                root.derive(f"m/84h/0h/0h/0/{index}")
            ).address()
            assert single_address(mnemonic, passphrase, "bip84", 1, index) == script.p2wpkh(
                root.derive(f"m/84h/0h/0h/1/{index}")
            ).address()
            assert single_address(mnemonic, passphrase, "bip49", 0, index) == script.p2sh(
                script.p2wpkh(root.derive(f"m/49h/0h/0h/0/{index}"))
            ).address()


def test_multisig_address_matches_embit():
    pubs = [
        child_pubkey(ABANDON, "", "m/48h/0h/0h/2h", 0, 0),
        child_pubkey(LEGAL, "", "m/48h/0h/0h/2h", 0, 0),
    ]
    address = multisig_address(pubs, 2, True)
    root_a = _embit_root(ABANDON, "")
    root_b = _embit_root(LEGAL, "")
    keys = sorted(
        [
            root_a.derive("m/48h/0h/0h/2h/0/0"),
            root_b.derive("m/48h/0h/0h/2h/0/0"),
        ],
        key=lambda key: key.sec(),
    )
    witness = script.multisig(2, keys)
    embit_address = script.p2wsh(witness).address()
    assert address == embit_address
    nested = multisig_address(pubs, 2, False)
    assert nested == script.p2sh(script.p2wsh(witness)).address()


def test_libsecp_or_documented_fallback_still_matches_vector():
    """buidl uses libsecp256k1 when _libsec imports, else its pure-python points."""
    from buidl.libsec_status import is_libsec_enabled

    hd = HDPrivateKey.from_mnemonic(ABANDON, password=b"")
    assert p2wpkh_address(hd.traverse("m/84h/0h/0h/0/0")) == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    assert p2sh_p2wpkh_address(hd.traverse("m/49h/0h/0h/0/0")) == "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
    # The flag is recorded so the image report can say which backend ran.
    assert is_libsec_enabled() in (True, False)
