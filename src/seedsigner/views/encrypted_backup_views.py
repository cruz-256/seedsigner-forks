"""Export and import an encrypted seed backup on a second card.

The OS microSD is never selected. Mounting happens only after the user
confirms the export or import action. Secrets stay on ``BackupFlowState``,
not in logged view arguments.
"""

from __future__ import annotations

import hmac
import logging

from gettext import gettext as _

from seedsigner.gui.screens import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    DireWarningScreen,
    LargeIconStatusScreen,
    WarningScreen,
    ErrorScreen,
    seed_screens,
)
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.hardware.backup_volume import (
    BackupIOError,
    BootDeviceRefused,
    NotSafeToRemove,
    backup_filename,
    format_volume_label,
    mounted_backup,
    scan_volumes,
)
from seedsigner.models.backup_seed import load_seed_from_payload
from seedsigner.models.backup_session import get_backup_flow_state
from seedsigner.models.encrypted_backup import (
    DecryptionError,
    EncryptedBackupError,
    MIN_ENCRYPTION_PASSPHRASE_CHARS,
    PayloadError,
    _MAX_FILE_BYTES,
    decrypt_seed_backup,
    encrypt_seed_backup,
    encryption_passphrase_is_acceptable,
    normalize_encryption_passphrase,
)
from seedsigner.models.seed import ElectrumSeed, Seed
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import Destination, BackStackView, MainMenuView, View

logger = logging.getLogger(__name__)


def _state_or_home():
    state = get_backup_flow_state()
    if state.seed is None and state.file_bytes == b"" and not state.volume_dev_node:
        return state, Destination(MainMenuView, clear_history=True)
    return state, None


def _passphrases_match(left: str, right: str) -> bool:
    left_bytes = normalize_encryption_passphrase(left).encode("utf-8")
    right_bytes = normalize_encryption_passphrase(right).encode("utf-8")
    if len(left_bytes) != len(right_bytes):
        return False
    return hmac.compare_digest(left_bytes, right_bytes)


class SeedEncryptedBackupIntroView(View):
    CONTINUE = ButtonOption("I understand")
    CANCEL = ButtonOption("Cancel")

    def __init__(self, seed: Seed):
        super().__init__()
        self.seed = seed

    def run(self):
        state = get_backup_flow_state()
        state.clear()
        state.seed = self.seed
        selected = self.run_screen(
            DireWarningScreen,
            title=_("Encrypted backup"),
            status_headline=_("Writes to a card"),
            text=_("Saves an encrypted seed file to a second card in a USB reader. The OS card is never written. Use a long passphrase. Test with a throwaway seed first."),
            button_data=[self.CONTINUE, self.CANCEL],
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON or selected is None:
            state.clear()
            return Destination(BackStackView)
        if [self.CONTINUE, self.CANCEL][selected] == self.CANCEL:
            state.clear()
            return Destination(BackStackView)
        if self.seed.has_passphrase:
            return Destination(SeedEncryptedBackupIncludePassphraseView)
        state.include_seed_passphrase = False
        return Destination(SeedEncryptedBackupPassphraseView)


class SeedEncryptedBackupIncludePassphraseView(View):
    INCLUDE = ButtonOption("Include passphrase")
    MNEMONIC_ONLY = ButtonOption("Mnemonic only")

    def run(self):
        state = get_backup_flow_state()
        if state.seed is None:
            state.clear()
            return Destination(MainMenuView, clear_history=True)
        selected = self.run_screen(
            WarningScreen,
            title=_("Seed passphrase"),
            status_headline=_("Optional"),
            text=_("Include this seed's passphrase in the encrypted file? Without it, the backup restores the mnemonic only."),
            button_data=[self.INCLUDE, self.MNEMONIC_ONLY],
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        state.include_seed_passphrase = [self.INCLUDE, self.MNEMONIC_ONLY][selected] == self.INCLUDE
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
        if not self.confirm:
            state.encryption_passphrase = ""
        elif not state.encryption_passphrase:
            return Destination(SeedEncryptedBackupPassphraseView, skip_current_view=True)
        title = "Confirm passphrase" if self.confirm else "Encrypt passphrase"
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
            if not encryption_passphrase_is_acceptable(entered):
                return Destination(SeedEncryptedBackupPassphraseRejectedView, view_args={"reason": "short"})
            state.encryption_passphrase = normalize_encryption_passphrase(entered)
            return Destination(SeedEncryptedBackupPassphraseView, view_args={"confirm": True})
        if not _passphrases_match(entered, state.encryption_passphrase):
            state.encryption_passphrase = ""
            return Destination(SeedEncryptedBackupPassphraseRejectedView, view_args={"reason": "mismatch"})
        return Destination(SeedEncryptedBackupInsertView)


class SeedEncryptedBackupPassphraseRejectedView(View):
    def __init__(self, reason: str):
        super().__init__()
        self.reason = reason

    def run(self):
        if self.reason == "short":
            text = _("Use at least {} characters. A short passphrase is easy to guess.").format(
                MIN_ENCRYPTION_PASSPHRASE_CHARS
            )
            headline = _("Too short")
        else:
            text = _("Those entries did not match. Enter the encryption passphrase again.")
            headline = _("Mismatch")
        self.run_screen(
            WarningScreen,
            title=_("Encryption passphrase"),
            status_headline=headline,
            text=text,
            show_back_button=False,
            button_data=[ButtonOption("Try again")],
        )
        return Destination(SeedEncryptedBackupPassphraseView, skip_current_view=True)


class SeedEncryptedBackupInsertView(View):
    SCAN = ButtonOption("Scan for card")

    def run(self):
        state = get_backup_flow_state()
        if not state.encryption_passphrase or state.seed is None:
            state.clear()
            return Destination(MainMenuView, clear_history=True)
        selected = self.run_screen(
            WarningScreen,
            title=_("Insert backup card"),
            status_headline=_("USB reader"),
            text=_("Plug a USB SD reader into the micro-USB port with an OTG adapter. Use a FAT card that is not the OS card."),
            button_data=[self.SCAN],
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return Destination(SeedEncryptedBackupSelectVolumeView)


class SeedEncryptedBackupSelectVolumeView(View):
    RETRY = ButtonOption("Retry")
    CANCEL = ButtonOption("Cancel")

    def run(self):
        state = get_backup_flow_state()
        if state.seed is None:
            state.clear()
            return Destination(MainMenuView, clear_history=True)
        try:
            scan = scan_volumes()
        except Exception:
            logger.exception("backup volume scan failed")
            scan = None
        if scan is None or not scan.eligible:
            if scan is not None and scan.refused_boot and not scan.eligible:
                text = _("Only the boot card is present, and it will not be written. Plug in a USB reader with a different card.")
                headline = _("Boot card refused")
            else:
                text = _("No USB card was found. Plug in the reader and retry. The OS card is ignored.")
                headline = _("No backup card")
            selected = self.run_screen(
                ErrorScreen,
                title=_("Encrypted backup"),
                status_headline=headline,
                text=text,
                button_data=[self.RETRY, self.CANCEL],
                show_back_button=True,
            )
            if selected == RET_CODE__BACK_BUTTON or [self.RETRY, self.CANCEL][selected] == self.CANCEL:
                return Destination(BackStackView)
            return Destination(SeedEncryptedBackupSelectVolumeView, skip_current_view=True)

        button_data = [ButtonOption(format_volume_label(volume), return_data=volume) for volume in scan.eligible]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Choose backup card"),
            button_data=button_data,
            is_bottom_list=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        volume = button_data[selected].return_data
        state.volume_dev_node = volume.dev_node
        state.volume_label = format_volume_label(volume)
        return Destination(SeedEncryptedBackupWriteView)


class SeedEncryptedBackupWriteView(View):
    WRITE = ButtonOption("Write backup")

    def run(self):
        state = get_backup_flow_state()
        if state.seed is None or not state.volume_dev_node or not state.encryption_passphrase:
            state.clear()
            return Destination(MainMenuView, clear_history=True)
        selected = self.run_screen(
            WarningScreen,
            title=_("Write backup"),
            status_headline=_("Check the card"),
            text=_("Write the encrypted file to {}? The screen will pause while the passphrase is stretched. Do not remove the card.").format(state.volume_label),
            button_data=[self.WRITE],
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        seed = state.seed
        try:
            filename = _write_backup(state)
        except BootDeviceRefused:
            logger.warning("refused encrypted backup write to boot or non-USB device")
            return Destination(
                SeedEncryptedBackupFailureView,
                view_args={"headline": "Write refused", "text": "That device is the boot card or is not a USB reader. Nothing was written.", "safe_to_remove": True},
            )
        except NotSafeToRemove:
            logger.error("backup card unmount failed")
            return Destination(
                SeedEncryptedBackupFailureView,
                view_args={"headline": "Still mounted", "text": "The card may still be mounted. Do not remove it. Restart the device, then unplug the reader.", "safe_to_remove": False},
            )
        except (BackupIOError, EncryptedBackupError, OSError):
            logger.exception("encrypted backup write failed")
            return Destination(
                SeedEncryptedBackupFailureView,
                view_args={"headline": "Write failed", "text": "Could not write the backup. If the card uses a format other than FAT, reformat it on another computer and try again.", "safe_to_remove": True},
            )
        state.clear()
        return Destination(
            SeedEncryptedBackupDoneView,
            view_args={"filename": filename, "seed": seed},
            skip_current_view=True,
        )


class SeedEncryptedBackupFailureView(View):
    def __init__(self, headline: str, text: str, safe_to_remove: bool):
        super().__init__()
        self.headline = headline
        self.text = text
        self.safe_to_remove = safe_to_remove

    def run(self):
        get_backup_flow_state().clear()
        self.run_screen(
            ErrorScreen,
            title=_("Encrypted backup"),
            status_headline=_(self.headline),
            text=_(self.text),
            button_data=[ButtonOption("OK")],
            show_back_button=False,
        )
        return Destination(MainMenuView, clear_history=True)


class SeedEncryptedBackupDoneView(View):
    def __init__(self, filename: str, seed: Seed):
        super().__init__()
        self.filename = filename
        self.seed = seed

    def run(self):
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Backup written"),
            status_headline=_("Safe to remove"),
            text=_("The file was synced and the card was unmounted. You can unplug the reader.\n{}").format(self.filename),
            button_data=[ButtonOption("Done")],
            show_back_button=False,
        )
        from seedsigner.views.seed_views import SeedOptionsView
        return Destination(SeedOptionsView, view_args={"seed": self.seed}, clear_history=True)


class SeedEncryptedImportIntroView(View):
    SCAN = ButtonOption("Scan for card")

    def run(self):
        state = get_backup_flow_state()
        state.clear()
        selected = self.run_screen(
            WarningScreen,
            title=_("Load backup"),
            status_headline=_("Second card"),
            text=_("Reads an encrypted backup from a USB card reader. The OS card is not used. You will enter the encryption passphrase after the file is read."),
            button_data=[self.SCAN],
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            state.clear()
            return Destination(BackStackView)
        return Destination(SeedEncryptedImportSelectVolumeView)


class SeedEncryptedImportSelectVolumeView(View):
    RETRY = ButtonOption("Retry")
    CANCEL = ButtonOption("Cancel")

    def run(self):
        try:
            scan = scan_volumes()
        except Exception:
            logger.exception("backup volume scan failed")
            scan = None
        if scan is None or not scan.eligible:
            text = _("No USB card was found. Plug in the reader and retry. The OS card is ignored.")
            if scan is not None and scan.refused_boot:
                text = _("Only the boot card is present, and it will not be read for this. Plug in a USB reader with the backup card.")
            selected = self.run_screen(
                ErrorScreen,
                title=_("Load backup"),
                status_headline=_("No backup card"),
                text=text,
                button_data=[self.RETRY, self.CANCEL],
                show_back_button=True,
            )
            if selected == RET_CODE__BACK_BUTTON or [self.RETRY, self.CANCEL][selected] == self.CANCEL:
                get_backup_flow_state().clear()
                return Destination(BackStackView)
            return Destination(SeedEncryptedImportSelectVolumeView, skip_current_view=True)
        button_data = [ButtonOption(format_volume_label(volume), return_data=volume) for volume in scan.eligible]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Choose backup card"),
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        volume = button_data[selected].return_data
        state = get_backup_flow_state()
        state.volume_dev_node = volume.dev_node
        state.volume_label = format_volume_label(volume)
        return Destination(SeedEncryptedImportSelectFileView)


class SeedEncryptedImportSelectFileView(View):
    def run(self):
        state = get_backup_flow_state()
        if not state.volume_dev_node:
            state.clear()
            return Destination(MainMenuView, clear_history=True)
        try:
            with mounted_backup(state.volume_dev_node, read_only=True) as mounted:
                names = mounted.list_backup_files()
        except BootDeviceRefused:
            return _import_io_destination("Boot card refused", "That device is the boot card or is not a USB reader.")
        except NotSafeToRemove:
            return _import_io_destination("Still mounted", "The card may still be mounted. Do not remove it. Restart, then unplug the reader.", safe_to_remove=False)
        except (BackupIOError, OSError):
            logger.exception("listing encrypted backups failed")
            return _import_io_destination("Cannot read card", "Could not read the card. It may need to be formatted FAT on another computer.")
        if not names:
            return _import_io_destination("No backup file", "No .ssenc file was found on that card.")
        button_data = [ButtonOption(name, return_data=name) for name in names]
        selected = self.run_screen(
            ButtonListScreen,
            title=_("Choose backup file"),
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        filename = button_data[selected].return_data
        try:
            with mounted_backup(state.volume_dev_node, read_only=True) as mounted:
                state.file_bytes = mounted.read_backup_file(filename, _MAX_FILE_BYTES)
        except BootDeviceRefused:
            state.clear()
            return _import_io_destination("Boot card refused", "That device is the boot card or is not a USB reader.")
        except NotSafeToRemove:
            state.clear()
            return _import_io_destination("Still mounted", "The card may still be mounted. Do not remove it. Restart, then unplug the reader.", safe_to_remove=False)
        except (BackupIOError, OSError):
            logger.exception("reading encrypted backup failed")
            state.clear()
            return _import_io_destination("Cannot read file", "Could not read that backup file.")
        state.filename = filename
        state.volume_dev_node = ""
        return Destination(SeedEncryptedImportSafeToRemoveView)


class SeedEncryptedImportSafeToRemoveView(View):
    def run(self):
        state = get_backup_flow_state()
        if not state.file_bytes:
            state.clear()
            return Destination(MainMenuView, clear_history=True)
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Backup read"),
            status_headline=_("Safe to remove"),
            text=_("The file is in memory and the card was unmounted. You can unplug the reader."),
            button_data=[ButtonOption("Enter passphrase")],
            show_back_button=False,
        )
        return Destination(SeedEncryptedImportPassphraseView)


class SeedEncryptedImportPassphraseView(View):
    def run(self):
        state = get_backup_flow_state()
        if not state.file_bytes:
            state.clear()
            return Destination(MainMenuView, clear_history=True)
        result = self.run_screen(
            seed_screens.SeedAddPassphraseScreen,
            passphrase="",
            custom_title="Decrypt passphrase",
        )
        if result.get("is_back_button"):
            state.clear()
            return Destination(MainMenuView, clear_history=True)
        entered = result.get("passphrase") or ""
        try:
            payload = decrypt_seed_backup(state.file_bytes, entered)
            seed = load_seed_from_payload(payload)
        except DecryptionError:
            return Destination(SeedEncryptedImportDecryptFailedView)
        except PayloadError:
            state.clear()
            return _import_io_destination("Not a valid seed", "The file decrypted, but the seed inside is not valid.")
        except EncryptedBackupError:
            state.clear()
            return _import_io_destination("Not a backup file", "That file is not a readable encrypted backup.")
        finally:
            entered = ""
        include = bool(payload.get("include_passphrase"))
        state.file_bytes = b""
        state.encryption_passphrase = ""
        state.seed = seed
        state.include_seed_passphrase = include
        return Destination(SeedEncryptedImportConfirmView)


class SeedEncryptedImportDecryptFailedView(View):
    RETRY = ButtonOption("Try again")
    CANCEL = ButtonOption("Cancel")

    def run(self):
        selected = self.run_screen(
            ErrorScreen,
            title=_("Load backup"),
            status_headline=_("Did not decrypt"),
            text=_("Wrong passphrase, or the file is damaged."),
            button_data=[self.RETRY, self.CANCEL],
            show_back_button=False,
        )
        if [self.RETRY, self.CANCEL][selected] == self.CANCEL:
            get_backup_flow_state().clear()
            return Destination(MainMenuView, clear_history=True)
        return Destination(SeedEncryptedImportPassphraseView, skip_current_view=True)


class SeedEncryptedImportConfirmView(View):
    LOAD = ButtonOption("Load seed")
    CANCEL = ButtonOption("Cancel", button_label_color="red")

    def run(self):
        state = get_backup_flow_state()
        seed = state.seed
        if seed is None:
            state.clear()
            return Destination(MainMenuView, clear_history=True)
        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
        fingerprint = seed.get_fingerprint(network)
        count = len(seed.mnemonic_list)
        kind = "Electrum" if isinstance(seed, ElectrumSeed) else "BIP-39"
        if state.include_seed_passphrase:
            text = _("{}-word {}. The seed passphrase from the file will be loaded too.").format(count, kind)
        else:
            text = _("{}-word {}. The file does not include a seed passphrase.").format(count, kind)
        selected = self.run_screen(
            WarningScreen,
            title=_("Load this seed?"),
            status_headline=fingerprint,
            text=text,
            button_data=[self.LOAD, self.CANCEL],
            show_back_button=False,
        )
        if [self.LOAD, self.CANCEL][selected] == self.CANCEL:
            state.clear()
            return Destination(MainMenuView, clear_history=True)
        self.controller.storage.set_pending_seed(seed)
        loaded = self.controller.storage.finalize_pending_seed()
        state.clear()
        from seedsigner.views.seed_views import SeedOptionsView
        return Destination(SeedOptionsView, view_args={"seed": loaded}, clear_history=True)


def _import_io_destination(headline: str, text: str, safe_to_remove: bool = True):
    return Destination(
        SeedEncryptedBackupFailureView,
        view_args={"headline": headline, "text": text, "safe_to_remove": safe_to_remove},
    )


def _write_backup(state) -> str:
    seed = state.seed
    seed_type = "electrum" if isinstance(seed, ElectrumSeed) else "bip39"
    seed_passphrase = seed.passphrase if state.include_seed_passphrase else ""
    blob = encrypt_seed_backup(
        mnemonic=seed.mnemonic_str,
        seed_type=seed_type,
        seed_passphrase=seed_passphrase,
        include_seed_passphrase=state.include_seed_passphrase,
        encryption_passphrase=state.encryption_passphrase,
    )
    filename = backup_filename()
    dev_node = state.volume_dev_node
    # Drop the encryption passphrase before the card write so a crash mid-write
    # does not keep it beside the ciphertext buffer any longer than necessary.
    state.encryption_passphrase = ""
    with mounted_backup(dev_node, read_only=False) as mounted:
        return mounted.write_backup_file(filename, blob)
