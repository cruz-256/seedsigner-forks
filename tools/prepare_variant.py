#!/usr/bin/env python3
"""Rewrite a copied app tree for the signer image or the Seed Viewer image.

The viewer tree deletes signing and seed-creation modules so they are not in
the image. The signer tree deletes the viewer package and vendored buidl.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path


VIEWER_DELETE = [
    "src/seedsigner/controller.py",
    "src/seedsigner/views/psbt_views.py",
    "src/seedsigner/views/seed_views.py",
    "src/seedsigner/views/tools_views.py",
    "src/seedsigner/views/scan_views.py",
    "src/seedsigner/models/psbt_parser.py",
    "src/seedsigner/models/seed.py",
    "src/seedsigner/models/decode_qr.py",
    "src/seedsigner/models/encode_qr.py",
    "src/seedsigner/gui/screens/psbt_screens.py",
    "src/seedsigner/gui/screens/tools_screens.py",
    "src/seedsigner/helpers/mnemonic_generation.py",
    "src/seedsigner/helpers/embit_utils.py",
    "src/seedsigner/helpers/ur2",
    "docs/dice_verification.md",
]

SIGNER_DELETE = [
    "src/seedviewer",
    "src/buidl",
]

VIEWER_FORBIDDEN_NAMES = {
    "psbt_views.py",
    "psbt_parser.py",
    "psbt_screens.py",
    "mnemonic_generation.py",
    "seed_views.py",
    "tools_views.py",
    "encode_qr.py",
}


def _rm(path: Path) -> None:
    if not path.exists():
        return
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def prepare(root: Path, variant: str) -> None:
    variant_file = root / "src" / "seedsigner" / "variant.py"
    variant_file.write_text(
        f'"""Which image this tree was built as. The viewer image build rewrites this."""\n\n'
        f'VARIANT = "{variant}"\n\n\n'
        f"def is_viewer() -> bool:\n"
        f'    return VARIANT == "viewer"\n'
    )
    if variant == "viewer":
        for relative in VIEWER_DELETE:
            _rm(root / relative)
        # Drop any PSBT or seed-creation file that a future edit might add.
        src = root / "src"
        for path in src.rglob("*"):
            if path.name in VIEWER_FORBIDDEN_NAMES:
                _rm(path)
    elif variant == "signer":
        for relative in SIGNER_DELETE:
            _rm(root / relative)
    else:
        raise SystemExit(f"unknown variant {variant}")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: prepare_variant.py <signer|viewer> <app root>", file=sys.stderr)
        return 2
    prepare(Path(argv[2]), argv[1])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
