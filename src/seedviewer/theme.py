"""Neon green on black, matching the colours named for sovereignstack.store.

Warning and danger stay red on the black background. Success is blue so it
does not disappear into the green theme. QR codes are drawn black on white
by the QR helper and are not recoloured here.
"""

from __future__ import annotations

from seedsigner.gui.components import Button, GUIConstants
from seedsigner.gui.screens.screen import (
    ErrorScreen,
    LargeIconStatusScreen,
    WarningScreen,
)


def _after(cls, values: dict, *, only_exact: bool = False):
    if "_viewer_themed" in cls.__dict__:
        return
    original = cls.__post_init__

    def post(self, *args, **kwargs):
        # Colour must be set before LargeIconStatusScreen draws its icon.
        if not only_exact or type(self) is cls:
            for key, value in values.items():
                setattr(self, key, value)
        original(self, *args, **kwargs)

    cls.__post_init__ = post
    cls._viewer_themed = True


def apply_viewer_theme() -> None:
    GUIConstants.BACKGROUND_COLOR = "#000000"
    GUIConstants.ACCENT_COLOR = "#00FF41"
    GUIConstants.NOTIFICATION_COLOR = "#39FF14"
    GUIConstants.BODY_FONT_COLOR = "#c8ffbc"
    GUIConstants.BUTTON_FONT_COLOR = "#c8ffbc"
    GUIConstants.BUTTON_SELECTED_FONT_COLOR = "#000000"
    GUIConstants.BUTTON_BACKGROUND_COLOR = "#0b3315"
    GUIConstants.INACTIVE_COLOR = "#145c25"
    GUIConstants.LABEL_FONT_COLOR = "#2f8f46"
    GUIConstants.WARNING_COLOR = "#FF2D2D"
    GUIConstants.DIRE_WARNING_COLOR = "#FF1B0A"
    GUIConstants.ERROR_COLOR = "#FF1B0A"
    GUIConstants.SUCCESS_COLOR = "#4DA3FF"
    GUIConstants.INFO_COLOR = "#39FF14"
    # Dataclass __init__ captured the stock colours. Reassign after init.
    _after(Button, {
        "background_color": "#0b3315",
        "selected_color": "#00FF41",
        "font_color": "#c8ffbc",
        "selected_font_color": "#000000",
    })
    _after(LargeIconStatusScreen, {"status_color": "#4DA3FF"}, only_exact=True)
    _after(WarningScreen, {"status_color": "#FF1B0A"})
    _after(ErrorScreen, {"status_color": "#FF1B0A"})
