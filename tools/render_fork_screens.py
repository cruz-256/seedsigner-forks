#!/usr/bin/env python3
"""Render new and changed screens at 240x240 and 320x240 and fail if text clips."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# Hardware imports must see a stand-in GPIO before SeedSigner loads.
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from PIL import Image, ImageDraw  # noqa: E402

from seedsigner.gui.components import GUIConstants  # noqa: E402
from seedsigner.gui.screens import (  # noqa: E402
    ButtonListScreen,
    DireWarningScreen,
    LargeIconStatusScreen,
    WarningScreen,
)
from seedsigner.gui.screens.backup_screens import HoldToConfirmScreen  # noqa: E402
from seedsigner.gui.screens.screen import ButtonOption, ErrorScreen  # noqa: E402
from seedsigner.gui.screens import seed_screens  # noqa: E402
from seedsigner.gui.screens.settings_screens import SettingsEntryUpdateSelectionScreen  # noqa: E402
from seedsigner.gui.renderer import Renderer  # noqa: E402
from seedsigner.models.settings import Settings, SettingsConstants  # noqa: E402
from seedviewer.theme import apply_viewer_theme  # noqa: E402
from tests.screenshot_generator.utils import ScreenshotComplete, ScreenshotRenderer  # noqa: E402


OUT = Path(os.environ.get("SCREENSHOT_DIR", "/opt/cursor/artifacts/screenshots"))


class ClipHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.hits = []

    def emit(self, record):
        if "cannot fit" in record.getMessage():
            self.hits.append(record.getMessage().replace("\n", " "))


def _resize(width, height):
    if ScreenshotRenderer._instance is None:
        ScreenshotRenderer.configure_instance()
    renderer = ScreenshotRenderer.get_instance()
    renderer.canvas_width = width
    renderer.canvas_height = height
    renderer.canvas = Image.new("RGB", (width, height))
    renderer.draw = ImageDraw.Draw(renderer.canvas)
    Renderer.get_instance = lambda: renderer
    return renderer


def _keyboard(name, title):
    return (name, seed_screens.SeedAddPassphraseScreen, dict(passphrase="", custom_title=title))


def _screens(viewer: bool):
    from seedsigner.helpers.qr import QR

    shared = [
        ("intro", DireWarningScreen, dict(
            title="KEF backup" if not viewer else "New KEF",
            status_headline="Long passphrase",
            text="Krux KEF. Hand-copied QR. This SD slot only.",
            button_data=[ButtonOption("Continue")],
            show_back_button=True,
        )),
        ("label_menu", ButtonListScreen, dict(
            title="Backup label",
            button_data=[ButtonOption("No label"), ButtonOption("Add a label")],
        )),
        _keyboard("keyboard_label", "Backup label"),
        _keyboard("keyboard_passphrase", "KEF passphrase"),
        _keyboard("keyboard_confirm", "Confirm phrase"),
        _keyboard("keyboard_decrypt", "Decrypt phrase"),
        ("passphrase_short", WarningScreen, dict(
            title="KEF passphrase",
            status_headline="Too short",
            text="Use at least 8 characters. A short passphrase is easy to guess.",
            show_back_button=False,
            button_data=[ButtonOption("Try again")],
        )),
        ("passphrase_mismatch", WarningScreen, dict(
            title="KEF passphrase",
            status_headline="Mismatch",
            text="Those entries did not match. Enter the passphrase again.",
            show_back_button=False,
            button_data=[ButtonOption("Try again")],
        )),
        ("destination", ButtonListScreen, dict(
            title="Save KEF",
            button_data=[
                ButtonOption("KEF QR code"),
                ButtonOption("This SD card"),
                ButtonOption("Swap SD card"),
            ],
        )),
        ("warning_boot_card", DireWarningScreen, dict(
            title="Boot card",
            status_headline="Seed stays here",
            text="Encrypted seed stays on this boot card. Anyone with the card has the backup.",
            button_data=[ButtonOption("I understand")],
            show_back_button=True,
        )),
        ("swap", WarningScreen, dict(
            title="Swap SD card",
            status_headline="OS stays in RAM",
            text="Pull the boot card. Insert a blank FAT card. The slot checks once a second.",
            button_data=[ButtonOption("Card is in")],
            show_back_button=True,
        )),
        ("no_card", WarningScreen, dict(
            title="SD slot",
            status_headline="No card",
            text="No card is in the slot yet. Insert a FAT card and try again.",
            show_back_button=False,
            button_data=[ButtonOption("Try again")],
        )),
        ("still_boot_card", DireWarningScreen, dict(
            title="SD slot",
            status_headline="Still boot card",
            text="This is still the OS card. Remove it and insert the blank card.",
            show_back_button=True,
            button_data=[ButtonOption("Try again")],
        )),
        ("saved_os", LargeIconStatusScreen, dict(
            title="KEF saved",
            status_headline="On boot card",
            text="Saved savings.kef on the boot card. Anyone with the card has the backup.",
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )),
        ("saved", LargeIconStatusScreen, dict(
            title="KEF saved",
            status_headline="Safe to remove",
            text="Saved savings.kef. You can remove the card.",
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )),
        ("scan_back", WarningScreen, dict(
            title="Check the QR",
            status_headline="Scan it back",
            text="Scan the KEF QR you copied. It is decrypted and compared to this seed before success.",
            button_data=[ButtonOption("Scan KEF QR")],
            show_back_button=True,
        )),
        ("scan_mismatch", WarningScreen, dict(
            title="Check the QR",
            status_headline="Did not match",
            text="That QR did not decrypt to this seed. Check the copy and the passphrase.",
            show_back_button=False,
            button_data=[ButtonOption("Back")],
        )),
        ("qr_checked", LargeIconStatusScreen, dict(
            title="QR checked",
            status_headline="73c5da0a",
            text="The scanned QR decrypts to this seed. Label: savings",
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )),
        ("import_menu", ButtonListScreen, dict(
            title="KEF import",
            button_data=[
                ButtonOption("From this SD"),
                ButtonOption("Swap SD card"),
                ButtonOption("Scan KEF QR"),
                ButtonOption("Wipe a KEF file"),
            ],
        )),
        ("import_none", WarningScreen, dict(
            title="KEF import",
            status_headline="None found",
            text="No .kef file or Krux seeds.json entry is on this card.",
            show_back_button=False,
            button_data=[ButtonOption("Back")],
        )),
        ("choose_backup", ButtonListScreen, dict(
            title="Choose backup",
            button_data=[ButtonOption("savings.kef"), ButtonOption("house.kef")],
        )),
        ("decrypt", WarningScreen, dict(
            title="Decrypt KEF",
            status_headline="savings",
            text="Source: SD card. Label: savings.",
            button_data=[ButtonOption("Decrypt")],
            show_back_button=True,
        )),
        ("decrypt_failed", WarningScreen, dict(
            title="Decrypt KEF",
            status_headline="Failed",
            text="Wrong passphrase, or the backup is not a valid BIP39 KEF envelope.",
            show_back_button=False,
            button_data=[ButtonOption("Try again")],
        )),
        ("seed_loaded", LargeIconStatusScreen, dict(
            title="Seed loaded",
            status_headline="73c5da0a",
            text="Source: SD card. Label: savings.",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )),
        ("wipe_none", WarningScreen, dict(
            title="Wipe backup",
            status_headline="None found",
            text="There is no .kef file in seedsigner-backup on this card.",
            show_back_button=False,
            button_data=[ButtonOption("Back")],
        )),
        ("wipe_pick", ButtonListScreen, dict(
            title="Wipe backup",
            button_data=[ButtonOption("savings.kef"), ButtonOption("house.kef")],
        )),
        ("wipe", HoldToConfirmScreen, dict(filename="savings.kef")),
        ("wipe_done", LargeIconStatusScreen, dict(
            title="Wipe backup",
            status_headline="File removed",
            text="savings.kef was overwritten and deleted. Wear-levelling can keep a copy. Destroy the card to be certain.",
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )),
        ("error", ErrorScreen, dict(
            title="KEF backup",
            status_headline="Not written",
            text="No card is in the slot",
            button_data=[ButtonOption("Back")],
            show_back_button=True,
        )),
        ("select_button", SettingsEntryUpdateSelectionScreen, dict(
            display_name="Select button",
            help_text="Top button types the highlighted letter when the joystick does not click. A real click still works.",
            button_data=[ButtonOption("Top button"), ButtonOption("Joystick click")],
            checked_buttons=[0],
            settings_entry_type="select_1",
        )),
        ("backup_menu", ButtonListScreen, dict(
            title="Backup Seed",
            is_bottom_list=True,
            button_data=[
                ButtonOption("View seed words"),
                ButtonOption("Export as SeedQR"),
                ButtonOption("Encrypted KEF backup"),
            ],
        )),
        ("load_menu", ButtonListScreen, dict(
            title="Load a Seed",
            is_button_text_centered=False,
            button_data=[
                ButtonOption("Scan a SeedQR"),
                ButtonOption("Enter 12-word seed"),
                ButtonOption("Enter 24-word seed"),
                ButtonOption("Encrypted KEF backup"),
                ButtonOption("Create a seed"),
            ],
        )),
        ("electrum", WarningScreen, dict(
            title="KEF backup",
            status_headline="BIP39 only",
            text="Krux KEF stores a BIP39 seed. This Electrum seed cannot be exported as KEF.",
            show_back_button=False,
            button_data=[ButtonOption("Back")],
        )),
        ("qr_whole", seed_screens.SeedTranscribeSeedQRWholeQRScreen, dict(
            qr_data=b"kef-layout-check",
            num_modules=29,
            qr_background="#ffffff",
            qr_style=QR.STYLE__DEFAULT,
            screen_title="Transcribe KEF",
        )),
    ]
    if viewer:
        from seedviewer.views import SplashScreen
        shared.extend([
            ("splash", SplashScreen, dict()),
            ("viewer_menu", ButtonListScreen, dict(
                title="Seed Viewer",
                button_data=[
                    ButtonOption("Load KEF backup"),
                    ButtonOption("Show words"),
                    ButtonOption("Show SeedQR"),
                    ButtonOption("New KEF backup"),
                    ButtonOption("Xpubs"),
                    ButtonOption("Check address"),
                    ButtonOption("Multisig"),
                    ButtonOption("BIP39 passphrase"),
                    ButtonOption("Compare backups"),
                    ButtonOption("Clear seed"),
                    ButtonOption("Wipe KEF file"),
                    ButtonOption("Settings"),
                ],
            )),
            _keyboard("keyboard_bip39", "BIP39 phrase"),
            ("viewer_settings", ButtonListScreen, dict(
                title="Settings",
                button_data=[
                    ButtonOption("Display 240"),
                    ButtonOption("Display 320"),
                    ButtonOption("KEY1 select"),
                    ButtonOption("Joystick click"),
                ],
            )),
        ])
    return shared


def _overflow(screen, width, height) -> list[str]:
    problems = []
    for component in getattr(screen, "components", []):
        bottom = getattr(component, "screen_y", 0) + getattr(component, "height", 0)
        right = getattr(component, "screen_x", 0) + getattr(component, "width", width)
        if bottom > height + 1:
            problems.append(f"component bottom {bottom} > {height}")
        if right > width + 1:
            problems.append(f"component right {right} > {width}")
    scrolls = bool(getattr(screen, "has_scroll_arrows", False))
    if not scrolls:
        for button in getattr(screen, "buttons", []) or []:
            bottom = button.screen_y + button.height
            if bottom > height + 1:
                problems.append(f"button bottom {bottom} > {height}")
    return problems


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    clip = ClipHandler()
    logging.getLogger("seedsigner.gui.components").addHandler(clip)
    logging.getLogger("seedsigner.gui.components").setLevel(logging.WARNING)
    Settings.get_instance()
    failures = []
    import seedsigner.variant as variant
    for viewer, theme_name in ((False, "signer"), (True, "viewer")):
        variant.VARIANT = "viewer" if viewer else "signer"
        if viewer:
            apply_viewer_theme()
        else:
            GUIConstants.BACKGROUND_COLOR = "#000000"
            GUIConstants.ACCENT_COLOR = "#FF9F0A"
            GUIConstants.WARNING_COLOR = "#FFD60A"
            GUIConstants.DIRE_WARNING_COLOR = "#FF5700"
            GUIConstants.SUCCESS_COLOR = "#30D158"
            GUIConstants.BODY_FONT_COLOR = "#FCFCFC"
            GUIConstants.BUTTON_BACKGROUND_COLOR = "#2C2C2C"
        for width, height, size_name in ((240, 240, "240"), (320, 240, "320")):
            Settings.get_instance().set_value(
                SettingsConstants.SETTING__DISPLAY_CONFIGURATION,
                SettingsConstants.DISPLAY_CONFIGURATION__ST7789__240x240
                if width == 240
                else SettingsConstants.DISPLAY_CONFIGURATION__ST7789__320x240,
            )
            renderer = _resize(width, height)
            for name, cls, kwargs in _screens(viewer):
                clip.hits.clear()
                renderer.set_screenshot_path(str(OUT))
                renderer.set_screenshot_filename(f"{theme_name}_{size_name}_{name}.png")
                screen = cls(**kwargs)
                try:
                    screen.display()
                except ScreenshotComplete:
                    pass
                problems = _overflow(screen, width, height) + list(clip.hits)
                if problems:
                    failures.append(f"{theme_name} {size_name} {name}: {problems}")
    if failures:
        print("CLIPPING")
        for line in failures:
            print(line)
        return 1
    print(f"rendered {len(list(OUT.glob('*.png')))} screenshots in {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
