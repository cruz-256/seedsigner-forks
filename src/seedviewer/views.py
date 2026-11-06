"""Seed Viewer screens. No seed creation and no signing."""

from __future__ import annotations

import hmac

from gettext import gettext as _

from seedsigner.gui.components import GUIConstants
from seedsigner.gui.screens import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    DireWarningScreen,
    LargeIconStatusScreen,
    WarningScreen,
    seed_screens,
)
from seedsigner.gui.screens.backup_screens import HoldToConfirmScreen
from seedsigner.gui.screens.screen import BaseScreen, ButtonOption
from seedsigner.gui.screens.scan_screens import ScanScreen
from seedsigner.hardware.backup_volume import (
    BackupVolumeError,
    filename_for_label,
    inspect_slot,
    request_slot_rescan,
)
from seedsigner.helpers.qr import QR
from seedsigner.models.bip39_words import entropy_to_mnemonic, mnemonic_to_entropy
from seedsigner.models.encrypted_backup import (
    MIN_ENCRYPTION_PASSPHRASE_CHARS,
    DecryptionError,
    EncryptedBackupError,
    PayloadError,
    decrypt_seed_backup,
    encrypt_seed_backup,
    preview_kef_label,
)
from seedsigner.models.kef_qr import KefQRDecoder, TextQRDecoder, kef_qr_modules
from seedsigner.models.settings import Settings, SettingsConstants
from seedviewer.derive import (
    bip48_account,
    bip49_account,
    bip84_account,
    child_pubkey,
    fingerprint,
    multisig_address,
    seedqr_digits,
    single_address,
)
from seedviewer.state import ViewerState, get_viewer_state


slot_reader = inspect_slot


class ViewerView:
    def __init__(self):
        self.settings = Settings.get_instance()
        self.state = get_viewer_state()

    def run_screen(self, screen_cls, **kwargs):
        return screen_cls(**kwargs).display()


class SplashView(ViewerView):
    def run(self):
        self.run_screen(SplashScreen)
        return MainView()


class SplashScreen(BaseScreen):
    def _render(self):
        super()._render()
        from seedsigner.gui.components import Fonts, TextArea

        TextArea(
            text=_("Seed Viewer"),
            font_name=GUIConstants.get_top_nav_title_font_name(),
            font_size=GUIConstants.get_top_nav_title_font_size() + 8,
            font_color=GUIConstants.ACCENT_COLOR,
            is_text_centered=True,
            screen_y=int(self.canvas_height * 0.38),
        ).render()
        TextArea(
            text=_("Verify only"),
            font_color=GUIConstants.BODY_FONT_COLOR,
            is_text_centered=True,
            screen_y=int(self.canvas_height * 0.55),
        ).render()

    def _run(self):
        import time
        from seedsigner.hardware.buttons import HardwareButtonsConstants
        time.sleep(0.2)
        self.hw_inputs.wait_for(HardwareButtonsConstants.KEYS__ANYCLICK)
        return 0


class MainView(ViewerView):
    def run(self):
        buttons = [ButtonOption("Load KEF backup")]
        if self.state.loaded:
            buttons.extend([
                ButtonOption("Show words"),
                ButtonOption("Show SeedQR"),
                ButtonOption("New KEF backup"),
                ButtonOption("Xpubs"),
                ButtonOption("Check address"),
                ButtonOption("Multisig"),
                ButtonOption("BIP39 passphrase"),
                ButtonOption("Compare backups"),
                ButtonOption("Clear seed"),
            ])
        else:
            buttons.append(ButtonOption("Compare backups"))
        buttons.extend([
            ButtonOption("Wipe KEF file"),
            ButtonOption("Settings"),
        ])
        selected = self.run_screen(ButtonListScreen, title=_("Seed Viewer"), button_data=buttons)
        if selected == RET_CODE__BACK_BUTTON:
            return self
        label = buttons[selected].button_label
        routing = {
            "Load KEF backup": LoadMenuView,
            "Show words": WordsView,
            "Show SeedQR": SeedQRView,
            "New KEF backup": BackupIntroView,
            "Xpubs": XpubMenuView,
            "Check address": AddressMenuView,
            "Multisig": MultisigMenuView,
            "BIP39 passphrase": PassphraseView,
            "Compare backups": CompareIntroView,
            "Clear seed": ClearView,
            "Wipe KEF file": WipePickView,
            "Settings": SettingsView,
        }
        return routing[label]()


class LoadMenuView(ViewerView):
    def run(self):
        buttons = [
            ButtonOption("From this SD"),
            ButtonOption("Swap SD card"),
            ButtonOption("Scan KEF QR"),
        ]
        selected = self.run_screen(ButtonListScreen, title=_("Load KEF"), button_data=buttons)
        if selected == RET_CODE__BACK_BUTTON:
            return MainView()
        if selected == 2:
            return ScanKefView()
        self.state.source = "sd"
        if selected == 1:
            return SwapInstructionView(next_view=PickFileView)
        return PickFileView()


class SwapInstructionView(ViewerView):
    def __init__(self, next_view):
        super().__init__()
        self.next_view = next_view

    def run(self):
        selected = self.run_screen(
            WarningScreen,
            title=_("Swap SD card"),
            status_headline=_("OS stays in RAM"),
            text=_("Pull the boot card. Insert the other FAT card. The slot checks once a second."),
            button_data=[ButtonOption("Card is in")],
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return MainView()
        request_slot_rescan()
        card = slot_reader()
        if card is None or card.is_os_card():
            self.run_screen(
                DireWarningScreen,
                title=_("SD slot"),
                status_headline=_("Not swapped"),
                text=_("The boot card is still in the slot, or the slot is empty."),
                show_back_button=False,
                button_data=[ButtonOption("Try again")],
            )
            return SwapInstructionView(self.next_view)
        return self.next_view()


class PickFileView(ViewerView):
    def run(self):
        try:
            card = slot_reader()
            if card is None:
                raise BackupVolumeError("No card is in the slot")
            choices = [(name, None) for name in card.list_kef()]
            for label, raw in card.list_krux_entries():
                choices.append((label, raw))
        except BackupVolumeError as exc:
            return notice(_("SD slot"), str(exc), MainView)
        if not choices:
            return notice(_("KEF import"), _("No .kef file or Krux entry was found."), MainView)
        buttons = [ButtonOption(name[:22]) for name, _raw in choices]
        selected = self.run_screen(ButtonListScreen, title=_("Choose backup"), button_data=buttons)
        if selected == RET_CODE__BACK_BUTTON:
            return MainView()
        name, raw = choices[selected]
        try:
            blob = raw if raw is not None else card.read_kef(name)
            preview = preview_kef_label(blob)
        except (BackupVolumeError, EncryptedBackupError) as exc:
            return notice(_("KEF import"), str(exc), MainView)
        self.state.file_bytes = blob
        self.state.label = preview["label"]
        self.state.source = "sd"
        return PreviewView()


class ScanKefView(ViewerView):
    def run(self):
        decoder = KefQRDecoder()
        self.run_screen(ScanScreen, instructions_text=_("Scan KEF QR"), decoder=decoder)
        if not decoder.complete:
            return MainView()
        try:
            preview = preview_kef_label(decoder.payload)
        except EncryptedBackupError as exc:
            return notice(_("KEF import"), str(exc), MainView)
        self.state.file_bytes = decoder.payload
        self.state.label = preview["label"]
        self.state.source = "qr"
        return PreviewView()


class PreviewView(ViewerView):
    def run(self):
        source = _("QR code") if self.state.source == "qr" else _("SD card")
        label = self.state.label or _("none")
        selected = self.run_screen(
            WarningScreen,
            title=_("Decrypt KEF"),
            status_headline=label[:18],
            text=_("Source: {source}. Label: {label}.").format(source=source, label=label),
            button_data=[ButtonOption("Decrypt")],
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return MainView()
        return DecryptView()


class DecryptView(ViewerView):
    def run(self):
        result = self.run_screen(
            seed_screens.SeedAddPassphraseScreen,
            passphrase="",
            custom_title=_("Decrypt phrase"),
        )
        if result.get("is_back_button"):
            return MainView()
        try:
            payload = decrypt_seed_backup(self.state.file_bytes, result.get("passphrase") or "")
        except (DecryptionError, PayloadError, EncryptedBackupError):
            return notice(_("Decrypt KEF"), _("Wrong passphrase, or not a BIP39 KEF envelope."), DecryptView)
        self.state.mnemonic = payload["mnemonic"]
        self.state.passphrase = ""
        self.state.label = payload["label"]
        fp = fingerprint(self.state.mnemonic, "")
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Seed loaded"),
            status_headline=fp,
            text=_("Source: {source}. Label: {label}.").format(
                source=_("QR code") if self.state.source == "qr" else _("SD card"),
                label=payload["label"] or _("none"),
            ),
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )
        return MainView()


class WordsView(ViewerView):
    def run(self):
        words = self.state.mnemonic.split()
        lines = " ".join(f"{i + 1}.{word}" for i, word in enumerate(words[:6]))
        # Page through 6 words at a time with left/right via a button list of pages.
        pages = []
        for start in range(0, len(words), 6):
            chunk = words[start:start + 6]
            pages.append(" ".join(f"{start + n + 1}.{w}" for n, w in enumerate(chunk)))
        index = 0
        while True:
            selected = self.run_screen(
                WarningScreen,
                title=_("Seed words"),
                status_headline=fingerprint(self.state.mnemonic, self.state.passphrase),
                text=pages[index],
                button_data=[ButtonOption("Next"), ButtonOption("Done")],
                show_back_button=True,
            )
            if selected == RET_CODE__BACK_BUTTON or selected == 1:
                return MainView()
            index = (index + 1) % len(pages)
        return MainView()


class SeedQRView(ViewerView):
    def run(self):
        digits = seedqr_digits(self.state.mnemonic)
        modules = kef_qr_modules(digits.encode("ascii"))
        selected = self.run_screen(
            seed_screens.SeedTranscribeSeedQRWholeQRScreen,
            qr_data=digits,
            num_modules=modules,
            qr_background="#ffffff",
            qr_style=QR.STYLE__DEFAULT,
            screen_title=_("SeedQR"),
        )
        if selected == RET_CODE__BACK_BUTTON:
            return MainView()
        self.run_screen(
            seed_screens.SeedTranscribeSeedQRZoomedInScreen,
            qr_data=digits,
            num_modules=modules,
            qr_background="#ffffff",
            qr_style=QR.STYLE__DEFAULT,
        )
        return MainView()


class PassphraseView(ViewerView):
    def run(self):
        result = self.run_screen(
            seed_screens.SeedAddPassphraseScreen,
            passphrase=self.state.passphrase,
            custom_title=_("BIP39 phrase"),
        )
        if result.get("is_back_button"):
            return MainView()
        self.state.passphrase = result.get("passphrase") or ""
        fp = fingerprint(self.state.mnemonic, self.state.passphrase)
        return notice(_("Fingerprint"), fp, MainView)


class XpubMenuView(ViewerView):
    def run(self):
        buttons = [
            ButtonOption("Native SegWit"),
            ButtonOption("Nested SegWit"),
            ButtonOption("Multisig native"),
            ButtonOption("Multisig nested"),
        ]
        selected = self.run_screen(ButtonListScreen, title=_("Xpubs"), button_data=buttons)
        if selected == RET_CODE__BACK_BUTTON:
            return MainView()
        makers = [bip84_account, bip49_account,
                  lambda m, p: bip48_account(m, p, True),
                  lambda m, p: bip48_account(m, p, False)]
        info = makers[selected](self.state.mnemonic, self.state.passphrase)
        text = _("{path} {slip_name} {slip}").format(**info)
        # The slip string is long. Show it in two screens.
        self.run_screen(
            WarningScreen,
            title=info["slip_name"],
            status_headline=info["fingerprint"],
            text=info["path"] + " " + info["slip"][:48],
            show_back_button=False,
            button_data=[ButtonOption("xpub")],
        )
        self.run_screen(
            WarningScreen,
            title=_("xpub"),
            status_headline=info["fingerprint"],
            text=info["xpub"][:72],
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return MainView()


class AddressMenuView(ViewerView):
    def __init__(self, kind: str = "bip84", change: int = 0, index: int = 0):
        super().__init__()
        self.kind = kind
        self.change = change
        self.index = index

    def run(self):
        address = single_address(self.state.mnemonic, self.state.passphrase, self.kind, self.change, self.index)
        chain = _("change") if self.change else _("receive")
        kind = _("Native") if self.kind == "bip84" else _("Nested")
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Address {n}").format(n=self.index),
            button_data=[
                ButtonOption(f"{kind} {chain}"),
                ButtonOption(address[:16] + "..."),
                ButtonOption("Next index"),
                ButtonOption("Change chain"),
                ButtonOption("Scan to check"),
                ButtonOption("Switch type"),
                ButtonOption("Done"),
            ],
        )
        if selected == RET_CODE__BACK_BUTTON or selected == 6:
            return MainView()
        if selected == 2:
            return AddressMenuView(self.kind, self.change, self.index + 1)
        if selected == 3:
            return AddressMenuView(self.kind, 1 - self.change, self.index)
        if selected == 5:
            other = "bip49" if self.kind == "bip84" else "bip84"
            return AddressMenuView(other, self.change, self.index)
        if selected == 4:
            decoder = TextQRDecoder()
            self.run_screen(ScanScreen, instructions_text=_("Scan address"), decoder=decoder)
            if decoder.complete and decoder.text == address:
                return notice(_("Address"), _("This address belongs to the loaded seed."), MainView)
            if decoder.complete:
                self.run_screen(
                    LargeIconStatusScreen,
                    title=_("Address"),
                    status_headline=_("No match"),
                    text=_("That QR is not this address."),
                    show_back_button=False,
                    button_data=[ButtonOption("Back")],
                )
            return AddressMenuView(self.kind, self.change, self.index)
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Address"),
            status_headline=f"{kind} {chain} {self.index}",
            text=address,
            show_back_button=False,
            button_data=[ButtonOption("Back")],
        )
        return AddressMenuView(self.kind, self.change, self.index)


class MultisigMenuView(ViewerView):
    def run(self):
        buttons = [ButtonOption("Native 2 of 2"), ButtonOption("Nested 2 of 3")]
        selected = self.run_screen(ButtonListScreen, title=_("Multisig"), button_data=buttons)
        if selected == RET_CODE__BACK_BUTTON:
            return MainView()
        native = selected == 0
        threshold = 2
        needed = 1 if native else 2
        pubs = [child_pubkey(self.state.mnemonic, self.state.passphrase,
                             "m/48h/0h/0h/2h" if native else "m/48h/0h/0h/1h", 0, 0)]
        info = bip48_account(self.state.mnemonic, self.state.passphrase, native)
        self.run_screen(
            WarningScreen,
            title=_("Your xpub"),
            status_headline=info["slip_name"],
            text=_("Scan {n} other xpub QR codes. Yours: {slip}").format(n=needed, slip=info["slip"][:40]),
            show_back_button=True,
            button_data=[ButtonOption("Scan cosigner")],
        )
        while len(pubs) < needed + 1:
            decoder = TextQRDecoder()
            self.run_screen(ScanScreen, instructions_text=_("Scan xpub"), decoder=decoder)
            if not decoder.complete:
                return MainView()
            sec = _xpub_child_sec(decoder.text)
            if sec is None:
                return notice(_("Multisig"), _("That QR is not an xpub this viewer can use."), MainView)
            pubs.append(sec)
        address = multisig_address(pubs, threshold, native)
        descriptor = _descriptor(info, threshold, native)
        self.run_screen(
            WarningScreen,
            title=_("Descriptor"),
            status_headline=_("receive 0"),
            text=descriptor[:140],
            show_back_button=False,
            button_data=[ButtonOption("Address")],
        )
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Multisig"),
            status_headline=address[:16],
            text=address,
            show_back_button=False,
            button_data=[ButtonOption("Scan to check")],
        )
        decoder = TextQRDecoder()
        self.run_screen(ScanScreen, instructions_text=_("Scan address"), decoder=decoder)
        if decoder.complete and decoder.text == address:
            return notice(_("Multisig"), _("That address matches this descriptor at index 0."), MainView)
        if decoder.complete:
            return notice(_("Multisig"), _("That address does not match index 0."), MainView)
        return MainView()


class BackupIntroView(ViewerView):
    def run(self):
        selected = self.run_screen(
            DireWarningScreen,
            title=_("New KEF"),
            status_headline=_("Long passphrase"),
            text=_("Krux KEF. Hand-copied QR. This SD slot only."),
            button_data=[ButtonOption("Continue")],
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON or selected == 1:
            return MainView()
        self.state.label = ""
        return BackupPassphraseView(confirm=False)


class BackupPassphraseView(ViewerView):
    def __init__(self, confirm: bool = False):
        super().__init__()
        self.confirm = confirm

    def run(self):
        title = _("Confirm phrase") if self.confirm else _("KEF passphrase")
        result = self.run_screen(seed_screens.SeedAddPassphraseScreen, passphrase="", custom_title=title)
        if result.get("is_back_button"):
            self.state.encryption_passphrase = ""
            return MainView()
        entered = result.get("passphrase") or ""
        if not self.confirm:
            if len(entered) < MIN_ENCRYPTION_PASSPHRASE_CHARS:
                return notice(_("KEF passphrase"), _("Use at least 8 characters."), BackupPassphraseView)
            self.state.encryption_passphrase = entered
            return BackupPassphraseView(confirm=True)
        if not hmac.compare_digest(entered.encode(), self.state.encryption_passphrase.encode()):
            self.state.encryption_passphrase = ""
            return notice(_("KEF passphrase"), _("Those entries did not match."), lambda: BackupPassphraseView(False))
        return BackupDestinationView()


class BackupDestinationView(ViewerView):
    def run(self):
        buttons = [ButtonOption("KEF QR code"), ButtonOption("This SD card"), ButtonOption("Swap SD card")]
        selected = self.run_screen(ButtonListScreen, title=_("Save KEF"), button_data=buttons)
        if selected == RET_CODE__BACK_BUTTON:
            return MainView()
        if selected == 0:
            return BackupQrView()
        if selected == 1:
            return OsCardWarningView()
        return SwapInstructionView(next_view=WriteCardView)


class OsCardWarningView(ViewerView):
    def run(self):
        selected = self.run_screen(
            DireWarningScreen,
            title=_("Boot card"),
            status_headline=_("Seed stays here"),
            text=_("Encrypted seed stays on this boot card. Anyone with the card has the backup."),
            button_data=[ButtonOption("I understand")],
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return BackupDestinationView()
        return WriteCardView(require_os=True)


class WriteCardView(ViewerView):
    def __init__(self, require_os: bool = False):
        super().__init__()
        self.require_os = require_os

    def run(self):
        try:
            card = slot_reader()
            if card is None:
                raise BackupVolumeError("No card is in the slot")
            if self.require_os and not card.is_os_card():
                raise BackupVolumeError("This is not the boot card")
            if not self.require_os and card.is_os_card():
                raise BackupVolumeError("Refusing to write the boot card")
            name = filename_for_label(self.state.label)
            blob = encrypt_seed_backup(
                mnemonic=self.state.mnemonic,
                encryption_passphrase=self.state.encryption_passphrase,
                label=self.state.label,
            )
            card.write_kef(name, blob)
        except (BackupVolumeError, PayloadError) as exc:
            self.state.encryption_passphrase = ""
            return notice(_("KEF backup"), str(exc), MainView)
        on_os = card.is_os_card()
        self.state.encryption_passphrase = ""
        text = (
            _("Saved {name} on the boot card. Anyone with the card has the backup.").format(name=name)
            if on_os else _("Saved {name}. You can remove the card.").format(name=name)
        )
        return notice(_("KEF saved"), text, MainView)


class BackupQrView(ViewerView):
    def run(self):
        try:
            blob = encrypt_seed_backup(
                mnemonic=self.state.mnemonic,
                encryption_passphrase=self.state.encryption_passphrase,
                label=self.state.label,
            )
        except PayloadError as exc:
            return notice(_("KEF backup"), str(exc), MainView)
        self.state.file_bytes = blob
        modules = kef_qr_modules(blob)
        selected = self.run_screen(
            seed_screens.SeedTranscribeSeedQRWholeQRScreen,
            qr_data=blob,
            num_modules=modules,
            qr_background="#ffffff",
            qr_style=QR.STYLE__DEFAULT,
            screen_title=_("Transcribe KEF"),
        )
        if selected == RET_CODE__BACK_BUTTON:
            return MainView()
        self.run_screen(
            seed_screens.SeedTranscribeSeedQRZoomedInScreen,
            qr_data=blob,
            num_modules=modules,
            qr_background="#ffffff",
            qr_style=QR.STYLE__DEFAULT,
        )
        return ScanBackView()


class ScanBackView(ViewerView):
    def run(self):
        selected = self.run_screen(
            WarningScreen,
            title=_("Check the QR"),
            status_headline=_("Scan it back"),
            text=_("Scan the KEF QR you copied. It must decrypt to this seed."),
            button_data=[ButtonOption("Scan KEF QR")],
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return MainView()
        decoder = KefQRDecoder()
        self.run_screen(ScanScreen, instructions_text=_("Scan KEF QR"), decoder=decoder)
        if not decoder.complete:
            return MainView()
        try:
            payload = decrypt_seed_backup(decoder.payload, self.state.encryption_passphrase)
            same = hmac.compare_digest(mnemonic_to_entropy(payload["mnemonic"]), mnemonic_to_entropy(self.state.mnemonic))
        except (DecryptionError, PayloadError, EncryptedBackupError, ValueError):
            same = False
        self.state.encryption_passphrase = ""
        if not same:
            return notice(_("Check the QR"), _("That QR did not decrypt to this seed."), MainView)
        return notice(_("QR checked"), fingerprint(self.state.mnemonic, self.state.passphrase), MainView)


class CompareIntroView(ViewerView):
    def run(self):
        self.run_screen(
            WarningScreen,
            title=_("Compare"),
            status_headline=_("Two backups"),
            text=_("Decrypt two KEF QR codes. Matching seeds show one fingerprint."),
            show_back_button=True,
            button_data=[ButtonOption("Scan first")],
        )
        first = _scan_entropy(self)
        if first is None:
            return MainView()
        self.run_screen(
            WarningScreen,
            title=_("Compare"),
            status_headline=first[1],
            text=_("Scan the second KEF QR."),
            show_back_button=False,
            button_data=[ButtonOption("Scan second")],
        )
        second = _scan_entropy(self)
        if second is None:
            return MainView()
        if hmac.compare_digest(first[0], second[0]):
            return notice(_("Compare"), _("Same seed. Fingerprint {fp}.").format(fp=first[1]), MainView)
        return notice(_("Compare"), _("Different seeds. {a} and {b}.").format(a=first[1], b=second[1]), MainView)


class WipePickView(ViewerView):
    def run(self):
        try:
            card = slot_reader()
            if card is None:
                raise BackupVolumeError("No card is in the slot")
            names = card.list_kef()
        except BackupVolumeError as exc:
            return notice(_("Wipe backup"), str(exc), MainView)
        if not names:
            return notice(_("Wipe backup"), _("No .kef file is on this card."), MainView)
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Wipe backup"),
            button_data=[ButtonOption(name) for name in names],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return MainView()
        held = self.run_screen(HoldToConfirmScreen, filename=names[selected])
        if held == RET_CODE__BACK_BUTTON:
            return MainView()
        try:
            card.wipe_kef(names[selected])
        except BackupVolumeError as exc:
            return notice(_("Wipe backup"), str(exc), MainView)
        return notice(
            _("Wipe backup"),
            _("Overwritten and deleted. Wear-levelling can keep a copy. Destroy the card to be certain."),
            MainView,
        )


class ClearView(ViewerView):
    def run(self):
        self.state.clear()
        return notice(_("Cleared"), _("The seed is gone from memory."), MainView)


class SettingsView(ViewerView):
    def run(self):
        buttons = [
            ButtonOption("Display 240"),
            ButtonOption("Display 320"),
            ButtonOption("KEY1 select"),
            ButtonOption("Joystick click"),
        ]
        selected = self.run_screen(ButtonListScreen, title=_("Settings"), button_data=buttons)
        if selected == RET_CODE__BACK_BUTTON:
            return MainView()
        if selected == 0:
            self.settings.set_value(
                SettingsConstants.SETTING__DISPLAY_CONFIGURATION,
                SettingsConstants.DISPLAY_CONFIGURATION__ST7789__240x240,
            )
            return notice(_("Display"), _("Saved 240x240. Restart to apply."), MainView)
        if selected == 1:
            self.settings.set_value(
                SettingsConstants.SETTING__DISPLAY_CONFIGURATION,
                SettingsConstants.DISPLAY_CONFIGURATION__ST7789__320x240,
            )
            return notice(_("Display"), _("Saved 320x240. Restart to apply."), MainView)
        value = SettingsConstants.INPUT_SELECT__KEY1 if selected == 2 else SettingsConstants.INPUT_SELECT__CLICK
        self.settings.set_value(SettingsConstants.SETTING__INPUT_SELECT, value)
        return notice(_("Select button"), _("Saved."), MainView)


def notice(title: str, text: str, nxt):
    view = _Notice(title, text, nxt)
    return view


class _Notice(ViewerView):
    def __init__(self, title: str, text: str, nxt):
        super().__init__()
        self.title = title
        self.text = text
        self.nxt = nxt

    def run(self):
        self.run_screen(
            LargeIconStatusScreen,
            title=self.title,
            status_headline=self.title[:18],
            text=self.text[:180],
            show_back_button=False,
            button_data=[ButtonOption("OK")],
        )
        target = self.nxt
        if isinstance(target, type):
            return target()
        if callable(target):
            made = target()
            return made if isinstance(made, ViewerView) else target
        return target


def _scan_entropy(view: ViewerView):
    decoder = KefQRDecoder()
    view.run_screen(ScanScreen, instructions_text=_("Scan KEF QR"), decoder=decoder)
    if not decoder.complete:
        return None
    try:
        preview = preview_kef_label(decoder.payload)
    except EncryptedBackupError:
        return None
    view.state.label = preview["label"]
    result = view.run_screen(
        seed_screens.SeedAddPassphraseScreen,
        passphrase="",
        custom_title=_("Decrypt phrase"),
    )
    if result.get("is_back_button"):
        return None
    try:
        payload = decrypt_seed_backup(decoder.payload, result.get("passphrase") or "")
        entropy = mnemonic_to_entropy(payload["mnemonic"])
    except (DecryptionError, PayloadError, EncryptedBackupError, ValueError):
        return None
    return entropy, fingerprint(payload["mnemonic"], "")


def _xpub_child_sec(text: str):
    """Accept an xpub/ypub/zpub/Ypub/Zpub and return the compressed key at /0/0."""
    from buidl.hd import HDPublicKey
    token = text.strip().split()[-1]
    try:
        node = HDPublicKey.parse(token)
        return node.child(0).child(0).sec()
    except Exception:
        return None


def _descriptor(info: dict, threshold: int, native: bool) -> str:
    kind = "wsh" if native else "sh(wsh"
    body = f"sortedmulti({threshold},[{info['fingerprint']}/{info['path'][2:]}]{info['slip']}/0/*)"
    if native:
        return f"wsh({body})"
    return f"sh(wsh({body}))"


def _loaded_entropy(state: ViewerState) -> bytes:
    return mnemonic_to_entropy(state.mnemonic)
