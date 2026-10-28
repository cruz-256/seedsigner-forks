#!/usr/bin/env python3
"""Decrypt a SeedSigner encrypted seed backup (.ssenc) off the device.

This script uses only the Python standard library plus
``src/seedsigner/models/encrypted_backup.py`` (or a copy of that file sitting
next to this script). It does not talk to the network.

The encryption passphrase is not the BIP-39 passphrase. Letter case matters.
The bytes are Unicode NFKD, then UTF-8, then scrypt, then AES-256-GCM. The
byte layout is documented in the module docstring and in the README.

Usage:
    python3 tools/decrypt_seed_backup.py seedsigner-backup-YYYYMMDDTHHMMSSZ.ssenc

If stdin is a terminal, the passphrase is read with no echo. Otherwise one
line is read from stdin so the script can be tested without a prompt:

    printf '%s\n' 'the encryption passphrase' | python3 tools/decrypt_seed_backup.py backup.ssenc

The mnemonic and, when the file includes it, the seed passphrase are printed
to stdout. Run this offline. A wrong passphrase or a damaged file exits 2
and does not print a seed.
"""

from __future__ import annotations

import getpass
import importlib.util
import sys
from pathlib import Path


def _load_format_module():
    here = Path(__file__).resolve().parent
    candidates = [
        here.parent / "src" / "seedsigner" / "models" / "encrypted_backup.py",
        here / "encrypted_backup.py",
    ]
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location("seedsigner_encrypted_backup", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    sys.stderr.write("Could not find encrypted_backup.py next to this script or in src/seedsigner/models.\n")
    raise SystemExit(1)


def _read_passphrase() -> str:
    if sys.stdin.isatty():
        return getpass.getpass("Encryption passphrase: ")
    return sys.stdin.readline().rstrip("\n")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] in {"-h", "--help"}:
        sys.stderr.write(__doc__)
        return 0 if len(argv) == 2 else 1
    path = Path(argv[1])
    try:
        blob = path.read_bytes()
    except OSError as exc:
        sys.stderr.write(f"Could not read {path.name}: {exc.strerror or exc}\n")
        return 1
    module = _load_format_module()
    passphrase = _read_passphrase()
    try:
        payload = module.decrypt_seed_backup(blob, passphrase)
    except module.DecryptionError:
        sys.stderr.write("Could not decrypt. Wrong passphrase, or the file was modified.\n")
        return 2
    except module.FormatError:
        sys.stderr.write("This is not an SSENC1 SeedSigner backup.\n")
        return 3
    except module.PayloadError:
        sys.stderr.write("The file decrypted, but the contents are not a usable seed payload.\n")
        return 3
    finally:
        passphrase = ""
    sys.stdout.write(f"seed_type: {payload['seed_type']}\n")
    sys.stdout.write(f"wordlist: {payload.get('wordlist', 'en')}\n")
    sys.stdout.write(f"include_passphrase: {'yes' if payload['include_passphrase'] else 'no'}\n")
    sys.stdout.write(f"mnemonic: {payload['mnemonic']}\n")
    if payload["include_passphrase"]:
        sys.stdout.write(f"passphrase: {payload['passphrase']}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
