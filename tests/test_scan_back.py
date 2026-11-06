"""Main-fork KEF scan-back: Cancel export, and the zoom-grid exit hint."""

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.models.backup_session import get_backup_flow_state
from seedsigner.views.encrypted_backup_views import (
    SeedEncryptedBackupQrZoomView,
    SeedEncryptedBackupScanBackCaptureView,
    SeedEncryptedBackupScanBackView,
)
from seedsigner.views.view import BackStackView, MainMenuView
from seedviewer.views import BackupQrView, ScanBackView


def _flow(**values):
    state = get_backup_flow_state()
    state.clear()
    for key, value in values.items():
        setattr(state, key, value)
    return state


def test_cancel_export_clears_the_in_memory_backup():
    state = _flow(encryption_passphrase="correct horse", file_bytes=b"secret", label="savings")
    view = SeedEncryptedBackupScanBackView.__new__(SeedEncryptedBackupScanBackView)
    seen = {}

    def run_screen(screen_cls, **kwargs):
        seen.update(kwargs)
        labels = [button.button_label for button in kwargs["button_data"]]
        return labels.index("Cancel export")

    view.run_screen = run_screen
    destination = view.run()

    assert [button.button_label for button in seen["button_data"]] == ["Scan KEF QR", "Cancel export"]
    assert destination.View_cls is MainMenuView
    assert destination.clear_history is True
    assert state.encryption_passphrase == ""
    assert state.file_bytes == b""
    assert state.label == ""


def test_scan_back_still_opens_the_camera_when_scan_is_selected():
    _flow(encryption_passphrase="correct horse", file_bytes=b"secret")
    view = SeedEncryptedBackupScanBackView.__new__(SeedEncryptedBackupScanBackView)
    view.run_screen = lambda *args, **kwargs: 0
    destination = view.run()
    assert destination.View_cls is SeedEncryptedBackupScanBackCaptureView


def test_scan_back_back_button_returns_to_the_grid():
    state = _flow(encryption_passphrase="correct horse", file_bytes=b"secret")
    view = SeedEncryptedBackupScanBackView.__new__(SeedEncryptedBackupScanBackView)
    view.run_screen = lambda *args, **kwargs: RET_CODE__BACK_BUTTON
    destination = view.run()
    assert destination.View_cls is BackStackView
    assert state.encryption_passphrase == "correct horse"


def test_kef_zoom_hint_is_press_any_button_to_exit():
    _flow(file_bytes=b"kef")
    view = SeedEncryptedBackupQrZoomView.__new__(SeedEncryptedBackupQrZoomView)
    view.num_modules = 29
    seen = {}

    def run_screen(screen_cls, **kwargs):
        seen["screen"] = screen_cls
        seen.update(kwargs)

    view.run_screen = run_screen
    destination = view.run()
    assert seen["exit_hint"] == "Press any button to exit"
    assert destination.View_cls.__name__ == "SeedEncryptedBackupScanBackView"


def test_viewer_scan_back_is_unchanged():
    view = ScanBackView.__new__(ScanBackView)
    seen = {}
    view.run_screen = lambda *args, **kwargs: seen.update(kwargs) or RET_CODE__BACK_BUTTON
    view.run()
    assert [button.button_label for button in seen["button_data"]] == ["Scan KEF QR"]
    assert "exit_hint" not in seen


def test_viewer_zoom_does_not_override_the_hint():
    source = BackupQrView.run.__code__.co_consts
    assert "Press any button to exit" not in source


def test_zoom_grid_exits_on_side_buttons_and_pans_on_directions():
    """Runs in a fresh interpreter so the screenshot suite's renderer mock stays out."""
    import os
    import subprocess
    import sys

    script = r"""
import sys
from unittest.mock import MagicMock
from PIL import Image, ImageDraw
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
    def show_image(self, image, x_start=0, y_start=0):
        return None
    def invert(self, enabled=True):
        return None
    def cleanup(self):
        return None

from seedsigner.hardware.displays.display_driver import DisplayDriverFactory
DisplayDriverFactory.instantiate_display_driver = classmethod(lambda cls, *a, **k: Display())
from seedsigner.models.settings import Settings
Settings.SETTINGS_FILENAME = "/tmp/seedsigner-zoom-hint-settings.json"
from seedsigner.gui.renderer import Renderer
Renderer.configure_instance()
renderer = Renderer.get_instance()
from seedsigner.gui.screens.seed_screens import SeedTranscribeSeedQRZoomedInScreen
from seedsigner.hardware.buttons import HardwareButtonsConstants
from seedsigner.helpers.qr import QR

screen_240 = None
for width in (240, 320):
    renderer.canvas_width = width
    renderer.canvas_height = 240
    renderer.canvas = Image.new("RGB", (width, 240))
    renderer.draw = ImageDraw.Draw(renderer.canvas)
    screen = SeedTranscribeSeedQRZoomedInScreen(
        qr_data=b"kef-layout-check",
        num_modules=29,
        qr_background="#ffffff",
        qr_style=QR.STYLE__DEFAULT,
        exit_hint="Press any button to exit",
    )
    assert screen.canvas_width == width
    bbox = screen.zone_mask.getchannel("A").getbbox()
    assert bbox is not None and bbox[0] >= 0 and bbox[2] <= width
    if width == 240:
        screen._render()
        presses = []
        def wait_for(keys=None):
            presses.append(1)
            if len(presses) == 1:
                return HardwareButtonsConstants.KEY_RIGHT
            return HardwareButtonsConstants.KEY1
        screen.hw_inputs.wait_for = wait_for
        assert screen._run() is None
        assert len(presses) == 2  # a direction pans; KEY1 exits. Joystick press was not required.
print("zoom-ok")
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = "/workspace/src"
    completed = subprocess.run([sys.executable, "-c", script], cwd="/workspace", env=env, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stdout + completed.stderr
