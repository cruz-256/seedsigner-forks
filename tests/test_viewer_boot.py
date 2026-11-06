"""The prepared viewer tree draws a splash without the deleted seed module."""

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_prepared_viewer_draws_a_screen(tmp_path):
    app = tmp_path / "app"
    shutil.copytree(ROOT / "src", app / "src", symlinks=True)
    spec_root = ROOT / "tools" / "prepare_variant.py"
    namespace = {}
    exec(spec_root.read_text(encoding="utf-8"), namespace)
    namespace["prepare"](app, "viewer")

    controller = (app / "src" / "seedviewer" / "controller.py").read_text(encoding="utf-8")
    assert "run_selftest" not in controller
    assert "selftest" not in controller
    assert not (app / "src" / "seedsigner" / "models" / "seed.py").exists()
    assert not (app / "src" / "seedsigner" / "controller.py").exists()
    assert (app / "src" / "seedsigner" / "resources" / "fonts" / "OpenSans-Regular.ttf").exists()
    assert not (app / "src" / "seedsigner" / "resources" / "seedsigner-translations" / "fonts" / "NotoSansSC-Regular.ttf").exists()
    assert not (app / "src" / "seedsigner" / "resources" / "seedsigner-translations" / "fonts" / "NotoSansJP-Regular.ttf").exists()
    assert not (app / "src" / "seedsigner" / "resources" / "seedsigner-translations" / "fonts" / "NotoSansKR-Regular.ttf").exists()
    l10n = app / "src" / "seedsigner" / "resources" / "seedsigner-translations" / "l10n"
    assert l10n.is_dir()
    assert list(l10n.iterdir()) == []

    script = textwrap.dedent(
        r"""
        import sys
        from unittest.mock import MagicMock

        gpio = MagicMock()
        gpio.RPI_INFO = {"P1_REVISION": 3}
        gpio.IN = 1
        gpio.PUD_UP = 1
        gpio.LOW = 0
        gpio.HIGH = 1
        gpio.BOARD = 1
        rpi = MagicMock()
        rpi.GPIO = gpio
        sys.modules["RPi"] = rpi
        sys.modules["RPi.GPIO"] = gpio
        sys.modules["spidev"] = MagicMock()

        class Display:
            width = 240
            height = 240
            image = None

            def show_image(self, image, x_start=0, y_start=0):
                self.image = image.copy()

            def invert(self, enabled=True):
                return None

            def cleanup(self):
                return None

        display = Display()
        from seedsigner.hardware.displays.display_driver import DisplayDriverFactory
        DisplayDriverFactory.instantiate_display_driver = classmethod(
            lambda cls, *args, **kwargs: display
        )
        from seedsigner.models.settings import Settings
        Settings.SETTINGS_FILENAME = "/tmp/seedsigner-viewer-boot-settings.json"

        import seedviewer.views
        import seedsigner.models.backup_seed
        import seedsigner.models.seed_storage
        import seedsigner.views.encrypted_backup_views
        assert "seedsigner.models.seed" not in sys.modules
        assert "seedviewer.selftest" not in sys.modules

        from seedsigner.hardware.buttons import HardwareButtons

        def wait_for(self, keys=None):
            raise SystemExit(0)

        HardwareButtons.wait_for = wait_for
        from seedviewer.controller import Controller
        try:
            Controller.get_instance().start()
        except SystemExit:
            pass
        image = display.image
        assert image is not None, "splash never reached the display"
        rgb = image.convert("RGB")
        nonblack = sum(1 for pixel in rgb.getdata() if pixel != (0, 0, 0))
        assert nonblack > 200, nonblack
        _red, green, _blue = rgb.getextrema()[0][1], rgb.getextrema()[1][1], rgb.getextrema()[2][1]
        assert green > 200
        """
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(app / "src")
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=app,
        env=env,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
