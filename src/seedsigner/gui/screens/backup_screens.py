"""Screens used by the KEF backup flow."""

from __future__ import annotations

import time
from dataclasses import dataclass

from gettext import gettext as _

from seedsigner.gui.screens.screen import (
    RET_CODE__BACK_BUTTON,
    ButtonOption,
    WarningScreen,
)
from seedsigner.hardware.buttons import HardwareButtonsConstants
from seedsigner.hardware.input_select import select_pressed


@dataclass
class HoldToConfirmScreen(WarningScreen):
    """Confirm by holding KEY1. KEY2, KEY3, or left cancels. Joystick click also holds."""

    filename: str = ""
    hold_seconds: float = 1.5

    def __post_init__(self):
        self.title = _("Wipe backup")
        self.status_headline = self.filename
        self.text = _("Cannot be undone. Wear-levelling can keep a copy. Destroy the card to be sure. KEY2 cancels.")
        self.show_back_button = False
        self.button_data = [ButtonOption("Hold KEY1")]
        super().__post_init__()

    def _run(self):
        started = None
        cancel_keys = {
            HardwareButtonsConstants.KEY_LEFT,
            HardwareButtonsConstants.KEY2,
            HardwareButtonsConstants.KEY3,
        }
        while True:
            held = False
            for key in (HardwareButtonsConstants.KEY1, HardwareButtonsConstants.KEY_PRESS):
                try:
                    if self.hw_inputs.check_for_low(key=key) and (
                        select_pressed(key) or key == HardwareButtonsConstants.KEY1
                    ):
                        held = True
                except Exception:
                    held = False
            if held:
                if started is None:
                    started = time.time()
                elif time.time() - started >= self.hold_seconds:
                    return 0
            else:
                started = None
            for key in cancel_keys:
                try:
                    if self.hw_inputs.check_for_low(key=key):
                        return RET_CODE__BACK_BUTTON
                except Exception:
                    pass
            time.sleep(0.05)
