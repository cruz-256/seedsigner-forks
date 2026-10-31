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
from seedsigner.gui.screens.screen import ButtonOption  # noqa: E402
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


def _screens(viewer: bool):
    title = "Seed Viewer" if viewer else "KEF backup"
    return [
        ("warning_boot_card", DireWarningScreen, dict(
            title="Boot card",
            status_headline="Seed stays here",
            text="Encrypted seed stays on this boot card. Anyone with the card has the backup.",
            button_data=[ButtonOption("I understand")],
            show_back_button=True,
        )),
        ("intro", DireWarningScreen, dict(
            title=title,
            status_headline="Long passphrase",
            text="Krux KEF. Hand-copied QR. This SD slot only.",
            button_data=[ButtonOption("Continue")],
            show_back_button=True,
        )),
        ("swap", WarningScreen, dict(
            title="Swap SD card",
            status_headline="OS stays in RAM",
            text="Pull the boot card. Insert a blank FAT card. The slot checks once a second.",
            button_data=[ButtonOption("Card is in")],
            show_back_button=True,
        )),
        ("wipe", HoldToConfirmScreen, dict(filename="savings.kef")),
        ("saved", LargeIconStatusScreen, dict(
            title="KEF saved",
            status_headline="Safe to remove",
            text="Saved savings.kef. You can remove the card.",
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )),
        ("menu", ButtonListScreen, dict(
            title=title,
            button_data=[
                ButtonOption("KEF QR code"),
                ButtonOption("This SD card"),
                ButtonOption("Swap SD card"),
                ButtonOption("Wipe a KEF file"),
            ],
        )),
        ("decrypt", WarningScreen, dict(
            title="Decrypt KEF",
            status_headline="savings",
            text="Source: SD card. Label: savings.",
            button_data=[ButtonOption("Decrypt")],
            show_back_button=True,
        )),
    ]


def _overflow(screen, width, height) -> list[str]:
    problems = []
    for component in getattr(screen, "components", []):
        bottom = getattr(component, "screen_y", 0) + getattr(component, "height", 0)
        right = getattr(component, "screen_x", 0) + getattr(component, "width", width)
        if bottom > height + 1:
            problems.append(f"component bottom {bottom} > {height}")
        if right > width + 1:
            problems.append(f"component right {right} > {width}")
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
    for viewer, theme_name in ((False, "signer"), (True, "viewer")):
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
