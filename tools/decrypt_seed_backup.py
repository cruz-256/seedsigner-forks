#!/usr/bin/env python3
"""Decrypt a Krux KEF envelope off the device.

The file is raw KEF bytes (the same bytes a KEF QR contains) or a one-entry
JSON object ``{"b64_kef": "..."}``. The passphrase is UTF-8 with no Unicode
normalization, matching Krux. It is not a BIP39 passphrase.

Usage:
    python3 tools/decrypt_seed_backup.py backup.kef

The passphrase is read without echo when stdin is a terminal. Otherwise one
line is read from stdin. A wrong passphrase exits 2 and prints no seed.
"""

from __future__ import annotations

import getpass
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from seedsigner.models.encrypted_backup import (  # noqa: E402
    DecryptionError,
    EncryptedBackupError,
    decrypt_seed_backup,
)


def _load(path: Path) -> bytes:
    data = path.read_bytes()
    if data.lstrip().startswith(b"{"):
        import base64
        import json
        parsed = json.loads(data.decode("utf-8"))
        if isinstance(parsed, dict) and "b64_kef" in parsed:
            return base64.b64decode(parsed["b64_kef"])
    return data


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: decrypt_seed_backup.py <file.kef>", file=sys.stderr)
        return 1
    if sys.stdin.isatty():
        passphrase = getpass.getpass("KEF passphrase: ")
    else:
        passphrase = sys.stdin.readline().rstrip("\n")
    try:
        payload = decrypt_seed_backup(_load(Path(argv[1])), passphrase)
    except (DecryptionError, EncryptedBackupError, OSError) as exc:
        print(f"decrypt failed: {exc}", file=sys.stderr)
        return 2
    print(payload["mnemonic"])
    if payload.get("label"):
        print(f"label: {payload['label']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
