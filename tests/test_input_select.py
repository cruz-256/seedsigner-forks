from seedsigner.hardware.input_select import next_match_index, next_passphrase_layout, select_pressed

# 40-pin header values. select_pressed also accepts the 26-pin joystick click (7).
KEY_PRESS = 33
KEY1 = 40
KEY2 = 38
KEY3 = 36
from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants, SettingsDefinition

from base import BaseTest


class TestInputSelect(BaseTest):
    def test_default_is_top_button_so_a_clickless_joystick_can_type(self):
        entry = SettingsDefinition.get_settings_entry(SettingsConstants.SETTING__INPUT_SELECT)
        assert entry.default_value == SettingsConstants.INPUT_SELECT__KEY1
        assert entry.visibility == SettingsConstants.VISIBILITY__HARDWARE
        BaseTest.reset_settings()
        assert Settings.get_instance().get_value(SettingsConstants.SETTING__INPUT_SELECT) == SettingsConstants.INPUT_SELECT__KEY1

    def test_select_pressed_accepts_joystick_click_in_both_modes(self):
        settings = Settings.get_instance()
        settings.set_value(SettingsConstants.SETTING__INPUT_SELECT, SettingsConstants.INPUT_SELECT__KEY1)
        assert select_pressed(KEY_PRESS) is True
        assert select_pressed(KEY1) is True
        assert select_pressed(KEY2) is False
        assert select_pressed(KEY3) is False
        assert select_pressed(7) is True  # 26-pin joystick click

        settings.set_value(SettingsConstants.SETTING__INPUT_SELECT, SettingsConstants.INPUT_SELECT__JOYSTICK)
        assert select_pressed(KEY_PRESS) is True
        assert select_pressed(KEY1) is False
        assert select_pressed(KEY2) is False
        assert select_pressed(KEY3) is False

    def test_passphrase_layout_cycle_keeps_every_charset_reachable_from_key2(self):
        seen = []
        current = "abc"
        for _ in range(5):
            current, _label = next_passphrase_layout(current)
            seen.append(current)
        assert seen == ["ABC", "123", "sym1", "sym2", "abc"]
        assert next_passphrase_layout("abc")[1] == "ABC"
        assert next_passphrase_layout("sym2")[1] == "abc"

    def test_word_list_wraps_only_when_key1_types(self):
        assert next_match_index(0, 4, wrap=False) == 1
        assert next_match_index(3, 4, wrap=False) == 3
        assert next_match_index(3, 4, wrap=True) == 0
        assert next_match_index(0, 0, wrap=True) == 0
