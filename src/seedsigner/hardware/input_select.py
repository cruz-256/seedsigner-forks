"""Decide which physical control types a highlighted letter.

Kept out of ``buttons.py`` so unit tests can use it without loading RPi.GPIO.
The test harness replaces ``seedsigner.hardware.buttons`` with a mock.
"""

from __future__ import annotations


# Passphrase keyboard order used when KEY1 is Select. KEY2's label is the next layout.
PASSPHRASE_LAYOUTS = (
    ("abc", "abc"),
    ("ABC", "ABC"),
    ("123", "123"),
    ("sym1", "!@#"),
    ("sym2", "*[]"),
)


def key1_is_select() -> bool:
    """True when the top side button types a letter, for hardware with no joystick click.

    A real center click is still accepted, so a normal five-way joystick keeps working.
    """
    try:
        from seedsigner.models.settings import Settings
        from seedsigner.models.settings_definition import SettingsConstants
        return Settings.get_instance().get_value(SettingsConstants.SETTING__INPUT_SELECT) == SettingsConstants.INPUT_SELECT__KEY1
    except Exception:
        return False


# Same board pin numbers as HardwareButtonsConstants. Duplicated so this module
# does not import buttons.py (unit tests replace that module with a mock, and
# it imports RPi.GPIO). 33/40 are the 40-pin header; 7/16 are the 26-pin header.
_JOYSTICK_CLICK_PINS = {33, 7}
_KEY1_PINS = {40, 16}


def select_pressed(key: int) -> bool:
    """True for the control that locks in the highlighted letter or activates Back."""
    if key in _JOYSTICK_CLICK_PINS:
        return True
    return key in _KEY1_PINS and key1_is_select()


def next_passphrase_layout(current_id: str) -> tuple:
    """Return ``(next_layout_id, its button label)``. KEY2 shows that label before the press."""
    ids = [item[0] for item in PASSPHRASE_LAYOUTS]
    index = ids.index(current_id)
    nxt = PASSPHRASE_LAYOUTS[(index + 1) % len(PASSPHRASE_LAYOUTS)]
    return nxt[0], nxt[1]


def next_match_index(index: int, count: int, wrap: bool) -> int:
    """Move down the seed-word candidate list. Wrap only when KEY1 is the select key."""
    if count <= 0:
        return 0
    nxt = index + 1
    if nxt >= count:
        return 0 if wrap else count - 1
    return nxt
