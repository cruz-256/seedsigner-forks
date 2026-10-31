"""Read and write KEF backups on the Pi Zero's built-in microSD slot.

The OS runs from RAM, so the slot can hold the boot card or a card swapped
in after boot. bcm2835-sdhost polls the slot. This module never uses USB.

A backup is a raw KEF envelope in ``seedsigner-backup/<name>.kef``. Boot
files are never overwritten. Krux ``seeds.json`` entries can be imported.
Wiping overwrites one file and then deletes it. Wear-levelling can keep an
older copy; the UI says so.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path


BACKUP_DIR_NAME = "seedsigner-backup"
OS_VOLUME_LABEL = "SEEDSIGNROS"
OS_CARD_MOUNT_POINT = "/mnt/microsd"
OS_CARD_DEVICE = "/dev/mmcblk0p1"
BOOT_FILENAMES = {
    "bootcode.bin",
    "start.elf",
    "start_x.elf",
    "fixup.dat",
    "fixup_x.dat",
    "zimage",
    "config.txt",
    "cmdline.txt",
}
_KEF_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,20}\.kef$")
_MAX_FILE_BYTES = 96 * 1024


class BackupVolumeError(Exception):
    """Base error. Messages name files, never file contents."""


class BootCardError(BackupVolumeError):
    """The card in the slot is not the kind the caller asked for."""


class BackupIOError(BackupVolumeError):
    """The card could not be read or written."""


def assert_kef_filename(name: str) -> str:
    if not isinstance(name, str) or _KEF_NAME.match(name) is None:
        raise BackupVolumeError("backup filename is not allowed")
    if name.lower() in BOOT_FILENAMES:
        raise BackupVolumeError("backup filename is not allowed")
    return name


def filename_for_label(label: str) -> str:
    cleaned = "".join(ch for ch in label.lower() if ch.isalnum())
    if not cleaned:
        cleaned = "seed"
    cleaned = cleaned[:16]
    return assert_kef_filename(f"{cleaned}.kef")


def fat_label_from_boot_sector(sector: bytes) -> str:
    """Return the FAT volume label from a 512-byte boot sector, or empty."""
    if len(sector) < 90:
        return ""
    if sector[66] == 0x29:
        raw = sector[71:82]
    elif sector[38] == 0x29:
        raw = sector[43:54]
    else:
        return ""
    return raw.split(b"\x00", 1)[0].decode("ascii", "ignore").strip()


@dataclass
class CardDirectory:
    """A FAT card root. Tests pass a temp directory; the device uses the mount."""

    root: str
    fat_label: str = ""

    def is_os_card(self) -> bool:
        if self.fat_label.strip().upper() == OS_VOLUME_LABEL:
            return True
        try:
            names = {name.lower() for name in os.listdir(self.root)}
        except OSError as exc:
            raise BackupIOError("SD card could not be read") from exc
        return bool(names & BOOT_FILENAMES)

    def _folder(self) -> str:
        return os.path.join(self.root, BACKUP_DIR_NAME)

    def list_kef(self) -> list[str]:
        folder = self._folder()
        if not os.path.isdir(folder):
            return []
        names = []
        for name in sorted(os.listdir(folder)):
            if _KEF_NAME.match(name):
                names.append(name)
        return names

    def read_kef(self, name: str) -> bytes:
        name = assert_kef_filename(name)
        path = os.path.join(self._folder(), name)
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            raise BackupIOError("backup could not be read") from exc
        if len(data) > _MAX_FILE_BYTES:
            raise BackupIOError("backup file is too large")
        return data

    def write_kef(self, name: str, data: bytes) -> str:
        name = assert_kef_filename(name)
        if len(data) > _MAX_FILE_BYTES or not data:
            raise BackupIOError("backup file is too large")
        folder = self._folder()
        os.makedirs(folder, exist_ok=True)
        final = os.path.join(folder, name)
        temporary = final + ".tmp"
        with open(temporary, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, final)
        _fsync_dir(folder)
        return name

    def wipe_kef(self, name: str) -> None:
        """Overwrite the file, then delete it. This cannot defeat wear-levelling."""
        name = assert_kef_filename(name)
        path = os.path.join(self._folder(), name)
        if not os.path.isfile(path):
            raise BackupIOError("backup file is not on the card")
        size = os.path.getsize(path)
        with open(path, "r+b") as handle:
            handle.write(secrets.token_bytes(size))
            handle.flush()
            os.fsync(handle.fileno())
            handle.seek(0)
            handle.write(b"\x00" * size)
            handle.flush()
            os.fsync(handle.fileno())
        os.remove(path)
        _fsync_dir(self._folder())

    def list_krux_entries(self) -> list[tuple[str, bytes]]:
        """Import helper for a Krux ``seeds.json`` of ``{id: {b64_kef: ...}}``."""
        path = os.path.join(self.root, "seeds.json")
        if not os.path.isfile(path):
            return []
        try:
            parsed = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise BackupIOError("seeds.json could not be read") from exc
        if not isinstance(parsed, dict):
            raise BackupIOError("seeds.json could not be read")
        found = []
        for label, entry in parsed.items():
            if not isinstance(entry, dict) or "b64_kef" not in entry:
                continue
            try:
                raw = base64.b64decode(entry["b64_kef"], validate=True)
            except Exception as exc:
                raise BackupIOError("seeds.json could not be read") from exc
            if len(raw) > _MAX_FILE_BYTES:
                raise BackupIOError("backup file is too large")
            found.append((str(label), raw))
        return found


def _fsync_dir(folder: str) -> None:
    try:
        descriptor = os.open(folder, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def request_slot_rescan(sysfs_root: str = "/sys") -> None:
    """Ask the kernel to poll the SD host. bcm2835-sdhost already polls."""
    host_root = os.path.join(sysfs_root, "class", "mmc_host")
    if not os.path.isdir(host_root):
        return
    for name in os.listdir(host_root):
        path = os.path.join(host_root, name, "rescan")
        try:
            with open(path, "w", encoding="ascii") as handle:
                handle.write("1")
        except OSError:
            continue


def read_device_fat_label(device: str = OS_CARD_DEVICE) -> str:
    try:
        with open(device, "rb") as handle:
            return fat_label_from_boot_sector(handle.read(512))
    except OSError:
        return ""


def inspect_slot(mount: str = OS_CARD_MOUNT_POINT, device: str = OS_CARD_DEVICE) -> CardDirectory | None:
    if not os.path.isdir(mount):
        return None
    return CardDirectory(mount, fat_label=read_device_fat_label(device))
