"""Screenshot clipping and the viewer tree strip."""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path


def _prepare():
    spec = importlib.util.spec_from_file_location(
        "prepare_variant",
        Path(__file__).resolve().parents[1] / "tools" / "prepare_variant.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.prepare


def test_viewer_tree_drops_signing_code(tmp_path):
    prepare = _prepare()
    root = tmp_path / "app"
    for relative in (
        "src/seedsigner/variant.py",
        "src/seedsigner/views/psbt_views.py",
        "src/seedsigner/views/seed_views.py",
        "src/seedsigner/helpers/mnemonic_generation.py",
        "src/seedsigner/models/psbt_parser.py",
        "src/seedviewer/controller.py",
        "src/buidl/hd.py",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x", encoding="utf-8")
    prepare(root, "viewer")
    assert (root / "src/seedsigner/variant.py").read_text(encoding="utf-8").count('VARIANT = "viewer"') == 1
    assert not (root / "src/seedsigner/views/psbt_views.py").exists()
    assert not (root / "src/seedsigner/views/seed_views.py").exists()
    assert not (root / "src/seedsigner/helpers/mnemonic_generation.py").exists()
    assert (root / "src/buidl/hd.py").exists()
    prepare(root, "signer")
    assert not (root / "src/seedviewer").exists()
    assert not (root / "src/buidl").exists()
    assert 'VARIANT = "signer"' in (root / "src/seedsigner/variant.py").read_text(encoding="utf-8")


def test_screens_do_not_clip():
    env = os.environ.copy()
    env["PYTHONPATH"] = "/workspace/src:."
    env["SCREENSHOT_DIR"] = "/tmp/fork-screens"
    completed = subprocess.run(
        [sys.executable, "tools/render_fork_screens.py"],
        cwd="/workspace",
        env=env,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    pngs = list(Path("/tmp/fork-screens").glob("*.png"))
    assert len(pngs) >= 28
