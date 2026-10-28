"""Turn a decrypted backup payload into an in-memory Seed.

Kept separate from ``encrypted_backup`` so that module stays free of embit and
can be imported by the standalone decrypt script.
"""

from __future__ import annotations

from seedsigner.models.encrypted_backup import PayloadError
from seedsigner.models.seed import ElectrumSeed, InvalidSeedException, Seed


def load_seed_from_payload(payload: dict) -> Seed:
    mnemonic = str(payload.get("mnemonic", "")).split()
    include = bool(payload.get("include_passphrase"))
    passphrase = payload.get("passphrase", "") if include else ""
    if not isinstance(passphrase, str):
        raise PayloadError("passphrase is missing")
    seed_type = payload.get("seed_type")
    try:
        if seed_type == "electrum":
            return ElectrumSeed(mnemonic=mnemonic, passphrase=passphrase)
        if seed_type == "bip39":
            return Seed(mnemonic=mnemonic, passphrase=passphrase)
    except InvalidSeedException as exc:
        raise PayloadError("seed is not valid") from exc
    raise PayloadError("unsupported seed type")
