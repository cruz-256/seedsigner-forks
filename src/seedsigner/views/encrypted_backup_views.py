"""Export and import a Krux KEF backup on the built-in SD slot or as a QR.

Nothing is written until the user confirms. An OS-card write shows a warning
first; leaving that screen writes nothing. Secrets stay on BackupFlowState.
"""

from __future__ import annotations

import hmac

from gettext import gettext as _

from seedsigner.gui.screens import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    DireWarningScreen,
    LargeIconStatusScreen,
    WarningScreen,
    seed_screens,
)
from seedsigner.gui.screens.backup_screens import HoldToConfirmScreen
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.hardware.backup_volume import (
    BackupIOError,
    BackupVolumeError,
    BootCardError,
    CardDirectory,
    filename_for_label,
    inspect_slot,
    request_slot_rescan,
)
from seedsigner.helpers.qr import QR
from seedsigner.models.backup_seed import load_seed_from_payload
from seedsigner.models.backup_session import get_backup_flow_state
from seedsigner.models.bip39_words import mnemonic_to_entropy
from seedsigner.models.encrypted_backup import (
    MIN_ENCRYPTION_PASSPHRASE_CHARS,
    DecryptionError,
    EncryptedBackupError,
    PayloadError,
    decrypt_seed_backup,
    encrypt_seed_backup,
    preview_kef_label,
)
from seedsigner.models.kef_qr import KefQRDecoder, kef_qr_modules
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import BackStackView, Destination, MainMenuView, View

# Tests replace this. The device reads the slot mdev already mounted.
slot_reader = inspect_slot


def _home_if_empty():
    state = get_backup_flow_state()
    if state.seed is None and not state.file_bytes and not state.encryption_passphrase:
        return Destination(MainMenuView, clear_history=True)
    return None


def _read_slot() -> CardDirectory | None:
    return slot_reader()


class SeedEncryptedBackupIntroView(View):
    CONTINUE = ButtonOption("Continue")

    def __init__(self, seed):
        super().__init__()
        self.seed = seed

    def run(self):
        from seedsigner.models.seed import ElectrumSeed

        state = get_backup_flow_state()
        state.clear()
        if isinstance(self.seed, ElectrumSeed):
            self.run_screen(
                WarningScreen,
                title=_("KEF backup"),
                status_headline=_("BIP39 only"),
                text=_("Krux KEF stores a BIP39 seed. This Electrum seed cannot be exported as KEF."),
                show_back_button=False,
                button_data=[ButtonOption("Back")],
            )
            return Destination(BackStackView)
        state.seed = self.seed
        selected = self.run_screen(
            DireWarningScreen,
            title=_("KEF backup"),
            status_headline=_("Long passphrase"),
            text=_("Krux KEF. Hand-copied QR. This SD slot only."),
            button_data=[self.CONTINUE],
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            state.clear()
            return Destination(BackStackView)
        return Destination(SeedEncryptedBackupLabelView)


class SeedEncryptedBackupLabelView(View):
    SKIP = ButtonOption("No label")
    ADD = ButtonOption("Add a label")

    def __init__(self, editing: bool = False):
        super().__init__()
        self.editing = editing

    def run(self):
        state = get_backup_flow_state()
        if state.seed is None:
            state.clear()
            return Destination(MainMenuView, clear_history=True)
        if not self.editing:
            selected = self.run_screen(
                ButtonListScreen,
                title=_("Backup label"),
                button_data=[self.SKIP, self.ADD],
            )
            if selected == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            if [self.SKIP, self.ADD][selected] == self.SKIP:
                state.label = ""
                return Destination(SeedEncryptedBackupPassphraseView)
        result = self.run_screen(
            seed_screens.SeedAddPassphraseScreen,
            passphrase="",
            custom_title=_("Backup label"),
        )
        if result.get("is_back_button"):
            return Destination(BackStackView)
        label = (result.get("passphrase") or "").strip()
        if len(label) > 20 or any(ord(ch) < 32 or ord(ch) > 126 for ch in label):
            self.run_screen(
                WarningScreen,
                title=_("Backup label"),
                status_headline=_("Too long"),
                text=_("Use up to 20 letters, numbers, or symbols from the keyboard."),
                show_back_button=False,
                button_data=[ButtonOption("Try again")],
            )
            return Destination(SeedEncryptedBackupLabelView, view_args={"editing": True}, skip_current_view=True)
        state.label = label
        return Destination(SeedEncryptedBackupPassphraseView)


class SeedEncryptedBackupPassphraseView(View):
    def __init__(self, confirm: bool = False):
        super().__init__()
        self.confirm = confirm

    def run(self):
        state = get_backup_flow_state()
        if state.seed is None:
            state.clear()
            return Destination(MainMenuView, clear_history=True)
        title = _("Confirm phrase") if self.confirm else _("KEF passphrase")
        result = self.run_screen(
            seed_screens.SeedAddPassphraseScreen,
            passphrase="",
            custom_title=title,
        )
        if result.get("is_back_button"):
            if self.confirm:
                state.encryption_passphrase = ""
            return Destination(BackStackView)
        entered = result.get("passphrase") or ""
        if not self.confirm:
            if len(entered) < MIN_ENCRYPTION_PASSPHRASE_CHARS:
                self.run_screen(
                    WarningScreen,
                    title=_("KEF passphrase"),
                    status_headline=_("Too short"),
                    text=_("Use at least {} characters. A short passphrase is easy to guess.").format(
                        MIN_ENCRYPTION_PASSPHRASE_CHARS
                    ),
                    show_back_button=False,
                    button_data=[ButtonOption("Try again")],
                )
                return Destination(SeedEncryptedBackupPassphraseView, skip_current_view=True)
            state.encryption_passphrase = entered
            return Destination(SeedEncryptedBackupPassphraseView, view_args={"confirm": True})
        if not hmac.compare_digest(entered.encode("utf-8"), state.encryption_passphrase.encode("utf-8")):
            state.encryption_passphrase = ""
            self.run_screen(
                WarningScreen,
                title=_("KEF passphrase"),
                status_headline=_("Mismatch"),
                text=_("Those entries did not match. Enter the passphrase again."),
                show_back_button=False,
                button_data=[ButtonOption("Try again")],
            )
            return Destination(SeedEncryptedBackupPassphraseView, skip_current_view=True)
        return Destination(SeedEncryptedBackupDestinationView)


class SeedEncryptedBackupDestinationView(View):
    QR = ButtonOption("KEF QR code")
    OS_CARD = ButtonOption("This SD card")
    SWAP = ButtonOption("Swap SD card")

    def run(self):
        state = get_backup_flow_state()
        if not state.encryption_passphrase or state.seed is None:
            state.clear()
            return Destination(MainMenuView, clear_history=True)
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Save KEF"),
            button_data=[self.QR, self.OS_CARD, self.SWAP],
        )
        if selected == RET_CODE__BACK_BUTTON:
            state.encryption_passphrase = ""
            return Destination(BackStackView)
        choice = [self.QR, self.OS_CARD, self.SWAP][selected]
        if choice == self.QR:
            state.destination = "qr"
            return Destination(SeedEncryptedBackupQrWholeView)
        if choice == self.OS_CARD:
            state.destination = "os"
            return Destination(SeedEncryptedBackupOsCardWarningView)
        state.destination = "swap"
        return Destination(SeedEncryptedBackupSwapView)


class SeedEncryptedBackupOsCardWarningView(View):
    UNDERSTAND = ButtonOption("I understand")

    def run(self):
        state = get_backup_flow_state()
        if state.destination != "os" or state.seed is None:
            return Destination(BackStackView)
        selected = self.run_screen(
            DireWarningScreen,
            title=_("Boot card"),
            status_headline=_("Seed stays here"),
            text=_("Encrypted seed stays on this boot card. Anyone with the card has the backup."),
            button_data=[self.UNDERSTAND],
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return Destination(SeedEncryptedBackupWriteView)


class SeedEncryptedBackupSwapView(View):
    READY = ButtonOption("Card is in")

    def run(self):
        selected = self.run_screen(
            WarningScreen,
            title=_("Swap SD card"),
            status_headline=_("OS stays in RAM"),
            text=_("Pull the boot card. Insert a blank FAT card. The slot checks once a second."),
            button_data=[self.READY],
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return Destination(SeedEncryptedBackupScanSlotView)


class SeedEncryptedBackupScanSlotView(View):
    def __init__(self, purpose: str = "export"):
        super().__init__()
        self.purpose = purpose

    def run(self):
        state = get_backup_flow_state()
        request_slot_rescan()
        try:
            card = _read_slot()
        except BackupVolumeError as exc:
            return _error(str(exc))
        if card is None:
            self.run_screen(
                WarningScreen,
                title=_("SD slot"),
                status_headline=_("No card"),
                text=_("No card is in the slot yet. Insert a FAT card and try again."),
                show_back_button=False,
                button_data=[ButtonOption("Try again")],
            )
            return Destination(SeedEncryptedBackupScanSlotView, view_args={"purpose": self.purpose}, skip_current_view=True)
        if self.purpose == "export" and state.destination == "swap" and card.is_os_card():
            self.run_screen(
                DireWarningScreen,
                title=_("SD slot"),
                status_headline=_("Still boot card"),
                text=_("This is still the OS card. Remove it and insert the blank card."),
                show_back_button=True,
                button_data=[ButtonOption("Try again")],
            )
            return Destination(SeedEncryptedBackupSwapView, skip_current_view=True)
        if self.purpose == "import" and state.destination == "swap" and card.is_os_card():
            self.run_screen(
                DireWarningScreen,
                title=_("SD slot"),
                status_headline=_("Still boot card"),
                text=_("This is still the OS card. Insert the card that holds the backup."),
                show_back_button=True,
                button_data=[ButtonOption("Try again")],
            )
            return Destination(SeedEncryptedImportSwapView, skip_current_view=True)
        if self.purpose == "export":
            return Destination(SeedEncryptedBackupWriteView)
        return Destination(SeedEncryptedImportPickView)


class SeedEncryptedBackupWriteView(View):
    def run(self):
        state = get_backup_flow_state()
        if state.seed is None or not state.encryption_passphrase:
            state.clear()
            return Destination(MainMenuView, clear_history=True)
        try:
            card = _read_slot()
            if card is None:
                raise BackupIOError("No card is in the slot")
            if state.destination == "os" and not card.is_os_card():
                raise BootCardError("This is not the boot card")
            if state.destination == "swap" and card.is_os_card():
                raise BootCardError("Refusing to write the boot card")
            name = filename_for_label(state.label)
            envelope = encrypt_seed_backup(
                mnemonic=state.seed.mnemonic_str,
                encryption_passphrase=state.encryption_passphrase,
                label=state.label,
            )
            card.write_kef(name, envelope)
        except (BackupVolumeError, PayloadError, EncryptedBackupError) as exc:
            state.encryption_passphrase = ""
            return _error(str(exc))
        on_os = card.is_os_card()
        state.encryption_passphrase = ""
        state.filename = name
        headline = _("On boot card") if on_os else _("Safe to remove")
        text = (
            _("Saved {name} on the boot card. Anyone with the card has the backup.").format(name=name)
            if on_os
            else _("Saved {name}. You can remove the card.").format(name=name)
        )
        self.run_screen(
            LargeIconStatusScreen,
            title=_("KEF saved"),
            status_headline=headline,
            text=text,
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        state.clear()
        return Destination(MainMenuView, clear_history=True)


class SeedEncryptedBackupQrWholeView(View):
    BEGIN = ButtonOption("Zoom in")

    def run(self):
        state = get_backup_flow_state()
        if state.seed is None or not state.encryption_passphrase:
            state.clear()
            return Destination(MainMenuView, clear_history=True)
        try:
            state.file_bytes = encrypt_seed_backup(
                mnemonic=state.seed.mnemonic_str,
                encryption_passphrase=state.encryption_passphrase,
                label=state.label,
            )
        except PayloadError as exc:
            return _error(str(exc))
        modules = kef_qr_modules(state.file_bytes)
        selected = self.run_screen(
            seed_screens.SeedTranscribeSeedQRWholeQRScreen,
            qr_data=state.file_bytes,
            num_modules=modules,
            qr_background="#ffffff",
            qr_style=QR.STYLE__DEFAULT,
            screen_title=_("Transcribe KEF"),
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return Destination(SeedEncryptedBackupQrZoomView, view_args={"num_modules": modules})


class SeedEncryptedBackupQrZoomView(View):
    def __init__(self, num_modules: int):
        super().__init__()
        self.num_modules = num_modules

    def run(self):
        state = get_backup_flow_state()
        if not state.file_bytes:
            return Destination(BackStackView)
        self.run_screen(
            seed_screens.SeedTranscribeSeedQRZoomedInScreen,
            qr_data=state.file_bytes,
            num_modules=self.num_modules,
            qr_background="#ffffff",
            qr_style=QR.STYLE__DEFAULT,
            # Side buttons leave the grid. A joystick click is accepted and not required.
            exit_hint=_("Press any button to exit"),
        )
        return Destination(SeedEncryptedBackupScanBackView)


class SeedEncryptedBackupScanBackView(View):
    SCAN = ButtonOption("Scan KEF QR")
    CANCEL = ButtonOption("Cancel export")

    def run(self):
        selected = self.run_screen(
            WarningScreen,
            title=_("Check the QR"),
            status_headline=_("Scan it back"),
            text=_("Scan the copied KEF QR. It must decrypt to this seed."),
            button_data=[self.SCAN, self.CANCEL],
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        if [self.SCAN, self.CANCEL][selected] == self.CANCEL:
            get_backup_flow_state().clear()
            return Destination(MainMenuView, clear_history=True)
        return Destination(SeedEncryptedBackupScanBackCaptureView)


class SeedEncryptedBackupScanBackCaptureView(View):
    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanScreen

        state = get_backup_flow_state()
        decoder = KefQRDecoder()
        self.run_screen(ScanScreen, instructions_text=_("Scan KEF QR"), decoder=decoder)
        if not decoder.complete:
            return Destination(BackStackView)
        try:
            payload = decrypt_seed_backup(decoder.payload, state.encryption_passphrase)
        except (DecryptionError, PayloadError, EncryptedBackupError):
            self.run_screen(
                WarningScreen,
                title=_("Check the QR"),
                status_headline=_("Did not match"),
                text=_("That QR did not decrypt to this seed. Check the copy and the passphrase."),
                show_back_button=False,
                button_data=[ButtonOption("Back")],
            )
            return Destination(SeedEncryptedBackupScanBackView, skip_current_view=True)
        try:
            same = hmac.compare_digest(
                mnemonic_to_entropy(payload["mnemonic"]),
                mnemonic_to_entropy(state.seed.mnemonic_str),
            )
        except ValueError:
            same = False
        if not same:
            self.run_screen(
                WarningScreen,
                title=_("Check the QR"),
                status_headline=_("Different seed"),
                text=_("The QR decrypted, but it is not this seed."),
                show_back_button=False,
                button_data=[ButtonOption("Back")],
            )
            return Destination(SeedEncryptedBackupScanBackView, skip_current_view=True)
        fingerprint = state.seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
        self.run_screen(
            LargeIconStatusScreen,
            title=_("QR checked"),
            status_headline=fingerprint,
            text=_("The scanned QR decrypts to this seed. Label: {label}").format(
                label=payload["label"] or _("none")
            ),
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        state.clear()
        return Destination(MainMenuView, clear_history=True)


class SeedEncryptedImportIntroView(View):
    SD = ButtonOption("From this SD")
    SWAP = ButtonOption("Swap SD card")
    QR = ButtonOption("Scan KEF QR")
    WIPE = ButtonOption("Wipe a KEF file")

    def run(self):
        get_backup_flow_state().clear()
        selected = self.run_screen(
            ButtonListScreen,
            title=_("KEF import"),
            button_data=[self.SD, self.SWAP, self.QR, self.WIPE],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        choice = [self.SD, self.SWAP, self.QR, self.WIPE][selected]
        state = get_backup_flow_state()
        if choice == self.QR:
            state.source = "qr"
            return Destination(SeedEncryptedImportScanView)
        if choice == self.WIPE:
            state.destination = "os"
            return Destination(SeedEncryptedWipePickView)
        if choice == self.SWAP:
            state.destination = "swap"
            state.source = "sd"
            return Destination(SeedEncryptedImportSwapView)
        state.destination = "os"
        state.source = "sd"
        return Destination(SeedEncryptedImportPickView)


class SeedEncryptedImportSwapView(View):
    READY = ButtonOption("Card is in")

    def run(self):
        selected = self.run_screen(
            WarningScreen,
            title=_("Swap SD card"),
            status_headline=_("OS stays in RAM"),
            text=_("Remove the boot card. Insert the FAT card with the backup. The slot is checked about once a second."),
            button_data=[self.READY],
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return Destination(SeedEncryptedBackupScanSlotView, view_args={"purpose": "import"})


class SeedEncryptedImportPickView(View):
    def run(self):
        state = get_backup_flow_state()
        try:
            card = _read_slot()
            if card is None:
                raise BackupIOError("No card is in the slot")
            choices = [(name, None) for name in card.list_kef()]
            for label, raw in card.list_krux_entries():
                choices.append((f"krux:{label}", raw))
        except BackupVolumeError as exc:
            return _error(str(exc))
        if not choices:
            self.run_screen(
                WarningScreen,
                title=_("KEF import"),
                status_headline=_("None found"),
                text=_("No .kef file or Krux seeds.json entry is on this card."),
                show_back_button=False,
                button_data=[ButtonOption("Back")],
            )
            return Destination(BackStackView)
        buttons = [ButtonOption(label[:24]) for label, _raw in choices]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Choose backup"),
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        name, raw = choices[selected]
        try:
            blob = raw if raw is not None else card.read_kef(name)
            preview = preview_kef_label(blob)
        except (BackupVolumeError, EncryptedBackupError) as exc:
            return _error(str(exc))
        state.file_bytes = blob
        state.filename = name
        state.label = preview["label"]
        state.source = "sd"
        return Destination(SeedEncryptedImportPreviewView)


class SeedEncryptedImportScanView(View):
    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanScreen

        decoder = KefQRDecoder()
        self.run_screen(ScanScreen, instructions_text=_("Scan KEF QR"), decoder=decoder)
        if not decoder.complete:
            return Destination(BackStackView)
        try:
            preview = preview_kef_label(decoder.payload)
        except EncryptedBackupError as exc:
            return _error(str(exc))
        state = get_backup_flow_state()
        state.file_bytes = decoder.payload
        state.label = preview["label"]
        state.source = "qr"
        state.filename = "QR"
        return Destination(SeedEncryptedImportPreviewView)


class SeedEncryptedImportPreviewView(View):
    DECRYPT = ButtonOption("Decrypt")

    def run(self):
        state = get_backup_flow_state()
        if not state.file_bytes:
            return Destination(BackStackView)
        source = _("QR code") if state.source == "qr" else _("SD card")
        label = state.label or _("none")
        selected = self.run_screen(
            WarningScreen,
            title=_("Decrypt KEF"),
            status_headline=label[:18],
            text=_("Source: {source}. Label: {label}.").format(
                source=source, label=label
            ),
            button_data=[self.DECRYPT],
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return Destination(SeedEncryptedImportPassphraseView)


class SeedEncryptedImportPassphraseView(View):
    def run(self):
        state = get_backup_flow_state()
        if not state.file_bytes:
            return Destination(BackStackView)
        result = self.run_screen(
            seed_screens.SeedAddPassphraseScreen,
            passphrase="",
            custom_title=_("Decrypt phrase"),
        )
        if result.get("is_back_button"):
            return Destination(BackStackView)
        try:
            payload = decrypt_seed_backup(state.file_bytes, result.get("passphrase") or "")
            seed = load_seed_from_payload(payload)
        except (DecryptionError, PayloadError, EncryptedBackupError):
            self.run_screen(
                WarningScreen,
                title=_("Decrypt KEF"),
                status_headline=_("Failed"),
                text=_("Wrong passphrase, or the backup is not a valid BIP39 KEF envelope."),
                show_back_button=False,
                button_data=[ButtonOption("Try again")],
            )
            return Destination(SeedEncryptedImportPassphraseView, skip_current_view=True)
        fingerprint = seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
        source = _("QR code") if state.source == "qr" else _("SD card")
        self.controller.storage.set_pending_seed(seed)
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Seed loaded"),
            status_headline=fingerprint,
            text=_("Source: {source}. Label: {label}.").format(
                source=source, label=payload["label"] or _("none")
            ),
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )
        state.clear()
        from seedsigner.views.seed_views import SeedFinalizeView
        return Destination(SeedFinalizeView, skip_current_view=True)


class SeedEncryptedWipePickView(View):
    def run(self):
        try:
            card = _read_slot()
            if card is None:
                raise BackupIOError("No card is in the slot")
            names = card.list_kef()
        except BackupVolumeError as exc:
            return _error(str(exc))
        if not names:
            self.run_screen(
                WarningScreen,
                title=_("Wipe backup"),
                status_headline=_("None found"),
                text=_("There is no .kef file in seedsigner-backup on this card."),
                show_back_button=False,
                button_data=[ButtonOption("Back")],
            )
            return Destination(BackStackView)
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Wipe backup"),
            button_data=[ButtonOption(name) for name in names],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return Destination(SeedEncryptedWipeConfirmView, view_args={"filename": names[selected]})


class SeedEncryptedWipeConfirmView(View):
    def __init__(self, filename: str):
        super().__init__()
        self.filename = filename

    def run(self):
        selected = self.run_screen(HoldToConfirmScreen, filename=self.filename)
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        try:
            card = _read_slot()
            if card is None:
                raise BackupIOError("No card is in the slot")
            card.wipe_kef(self.filename)
        except BackupVolumeError as exc:
            return _error(str(exc))
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Wipe backup"),
            status_headline=_("File removed"),
            text=_("{name} was overwritten and deleted. Wear-levelling can keep a copy. Destroy the card to be certain.").format(
                name=self.filename
            ),
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(MainMenuView, clear_history=True)


def _error(text: str) -> Destination:
    from seedsigner.views.view import ErrorView
    return Destination(
        ErrorView,
        view_args={
            "title": "KEF backup",
            "status_headline": "Not written",
            "text": text,
            "button_text": "Back",
            "next_destination": Destination(BackStackView, skip_current_view=True),
        },
    )

