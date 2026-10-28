"""Find a USB mass-storage card and read or write a backup file on it.

The Raspberry Pi Zero has one microSD slot. That slot is the OS card
(``mmcblk*``) and is never a valid target, whether or not it is mounted.
A second card is a USB reader on the OTG port and shows up as ``sd*`` whose
sysfs device sits under a USB bus or whose driver is ``usb-storage`` / ``uas``.

Nothing in this module mounts or writes until a caller asks it to. Import
mounts read-only. Export mounts read-write, fsyncs, syncs, and unmounts, and
raises ``NotSafeToRemove`` if the unmount does not stick.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass


logger = logging.getLogger(__name__)

BACKUP_MOUNT_POINT = "/mnt/seedsigner-backup"
OS_CARD_MOUNT_POINT = "/mnt/microsd"
FORBIDDEN_MOUNT_POINTS = {"/", "/boot", "/boot/firmware", OS_CARD_MOUNT_POINT}
BOOT_MOUNT_POINTS = FORBIDDEN_MOUNT_POINTS
_DEV_NAME = re.compile(r"^[A-Za-z0-9]+$")


class BackupVolumeError(Exception):
    """Base error. Messages name devices, never file contents."""


class BootDeviceRefused(BackupVolumeError):
    """The caller asked to use the OS card, the root device, or a non-USB disk."""


class BackupIOError(BackupVolumeError):
    """Mount, read, or write failed. The card should already be unmounted."""


class NotSafeToRemove(BackupVolumeError):
    """Unmount failed or the mount is still visible. Leave the card plugged in."""


@dataclass(frozen=True)
class Volume:
    disk_name: str
    volume_name: str
    dev_node: str
    is_usb_mass_storage: bool
    is_boot_related: bool
    size_bytes: int

    @property
    def is_eligible(self) -> bool:
        return volume_is_eligible(self)


@dataclass(frozen=True)
class VolumeScan:
    eligible: list
    refused_boot: list


def volume_is_eligible(volume: Volume) -> bool:
    """Pure check used by tests and by the writer immediately before mount."""
    if not volume.is_usb_mass_storage or volume.is_boot_related:
        return False
    if volume.disk_name.startswith("mmcblk") or volume.volume_name.startswith("mmcblk"):
        return False
    if not _DEV_NAME.match(volume.disk_name) or not _DEV_NAME.match(volume.volume_name):
        return False
    if volume.dev_node != f"/dev/{volume.volume_name}":
        return False
    return True


def parent_disk(name: str) -> str:
    """``sda1`` -> ``sda``, ``mmcblk0p1`` -> ``mmcblk0``, ``nvme0n1p2`` -> ``nvme0n1``."""
    if any(token in name for token in ("mmcblk", "nvme", "loop")):
        head, separator, part = name.rpartition("p")
        if separator and part.isdigit() and head:
            return head
        return name
    index = len(name)
    while index > 0 and name[index - 1].isdigit():
        index -= 1
    return name[:index] or name


def path_is_usb_mass_storage(device_realpath: str, driver_name: str | None) -> bool:
    if driver_name in {"usb-storage", "uas"}:
        return True
    for part in device_realpath.split("/"):
        if len(part) > 3 and part.startswith("usb") and part[3:].isdigit():
            return True
    return False


def boot_names_from_mounts(mounts_text: str) -> set[str]:
    names: set[str] = set()
    for line in mounts_text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        source, target = parts[0], parts[1]
        if target not in BOOT_MOUNT_POINTS or not source.startswith("/dev/"):
            continue
        name = source.rsplit("/", 1)[-1]
        if not name or name == "root":
            continue
        names.add(name)
        names.add(parent_disk(name))
    return names


def boot_names_from_cmdline(cmdline: str) -> set[str]:
    names: set[str] = set()
    for token in cmdline.split():
        if not token.startswith("root=/dev/"):
            continue
        name = token.split("root=/dev/", 1)[1]
        if not name or "/" in name:
            continue
        names.add(name)
        names.add(parent_disk(name))
    return names


def mounted_source(mounts_text: str, mount_point: str) -> str | None:
    target = mount_point.rstrip("/") or "/"
    for line in mounts_text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == target:
            return parts[0]
    return None


class SysfsBlockSource:
    """Read block devices from sysfs and proc. Tests use ``MemoryBlockSource``."""

    def __init__(self, sysfs: str = "/sys", proc: str = "/proc") -> None:
        self.sysfs = sysfs
        self.proc = proc

    def iter_disks(self) -> list[str]:
        block = os.path.join(self.sysfs, "block")
        try:
            names = os.listdir(block)
        except OSError:
            return []
        return sorted(name for name in names if _DEV_NAME.match(name))

    def partitions(self, disk: str) -> list[str]:
        base = os.path.join(self.sysfs, "block", disk)
        try:
            entries = os.listdir(base)
        except OSError:
            return []
        names = []
        for name in entries:
            if name != disk and name.startswith(disk) and _DEV_NAME.match(name):
                path = os.path.join(base, name)
                if os.path.isdir(path) or os.path.exists(os.path.join(path, "size")):
                    names.append(name)
        return sorted(names)

    def device_realpath(self, disk: str) -> str:
        return os.path.realpath(os.path.join(self.sysfs, "block", disk, "device"))

    def driver_name(self, disk: str) -> str | None:
        link = os.path.join(self.sysfs, "block", disk, "device", "driver")
        if not os.path.exists(link):
            return None
        return os.path.basename(os.path.realpath(link))

    def size_bytes(self, name: str) -> int:
        disk = parent_disk(name)
        if name == disk:
            path = os.path.join(self.sysfs, "block", disk, "size")
        else:
            path = os.path.join(self.sysfs, "block", disk, name, "size")
        try:
            with open(path, "r", encoding="ascii") as handle:
                sectors = int(handle.read().strip() or "0")
        except (OSError, ValueError):
            return 0
        return sectors * 512

    def read_mounts(self) -> str:
        return _read_text(os.path.join(self.proc, "mounts"))

    def read_cmdline(self) -> str:
        return _read_text(os.path.join(self.proc, "cmdline"))


class MemoryBlockSource:
    """Dict-backed sysfs stand-in for unit tests. Never touches /dev."""

    def __init__(self, disks: dict, mounts: str = "", cmdline: str = "") -> None:
        self.disks = disks
        self.mounts = mounts
        self.cmdline = cmdline

    def iter_disks(self) -> list[str]:
        return sorted(self.disks)

    def partitions(self, disk: str) -> list[str]:
        return sorted(self.disks[disk].get("partitions", {}))

    def device_realpath(self, disk: str) -> str:
        return self.disks[disk].get("realpath", "")

    def driver_name(self, disk: str) -> str | None:
        return self.disks[disk].get("driver")

    def size_bytes(self, name: str) -> int:
        for disk, info in self.disks.items():
            if name == disk:
                return int(info.get("size", 0))
            parts = info.get("partitions", {})
            if name in parts:
                return int(parts[name])
        return 0

    def read_mounts(self) -> str:
        return self.mounts

    def read_cmdline(self) -> str:
        return self.cmdline


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def list_volumes(source=None) -> list[Volume]:
    source = source or SysfsBlockSource()
    boot_names = boot_names_from_mounts(source.read_mounts())
    boot_names |= boot_names_from_cmdline(source.read_cmdline())
    volumes: list[Volume] = []
    for disk in source.iter_disks():
        try:
            realpath = source.device_realpath(disk)
            driver = source.driver_name(disk)
        except OSError:
            continue
        usb = path_is_usb_mass_storage(realpath, driver)
        parts = source.partitions(disk)
        targets = parts if parts else [disk]
        disk_is_boot = disk in boot_names or disk.startswith("mmcblk")
        for name in targets:
            boot = disk_is_boot or name in boot_names or name.startswith("mmcblk")
            volumes.append(Volume(
                disk_name=disk,
                volume_name=name,
                dev_node=f"/dev/{name}",
                is_usb_mass_storage=usb,
                is_boot_related=boot,
                size_bytes=source.size_bytes(name),
            ))
    return volumes


def scan_volumes(source=None) -> VolumeScan:
    volumes = list_volumes(source)
    eligible = [volume for volume in volumes if volume.is_eligible]
    refused = [volume.dev_node for volume in volumes if volume.is_boot_related]
    return VolumeScan(eligible=eligible, refused_boot=refused)


def assert_dev_node_eligible(dev_node: str, source) -> Volume:
    _reject_dev_node_shape(dev_node)
    for volume in list_volumes(source):
        if volume.dev_node == dev_node and volume.is_eligible:
            return volume
    raise BootDeviceRefused(dev_node)


def _reject_dev_node_shape(dev_node: str) -> None:
    if not isinstance(dev_node, str) or not dev_node.startswith("/dev/"):
        raise BootDeviceRefused("refused device node")
    name = dev_node[len("/dev/"):]
    if not _DEV_NAME.match(name) or name.startswith("mmcblk") or name.startswith("loop"):
        raise BootDeviceRefused(dev_node)
    # Missing nodes are fine here (unit tests, or the reader was just unplugged
    # and the later mount will fail). A node that exists must not be an alias
    # of the onboard microSD.
    if os.path.lexists(dev_node):
        resolved = os.path.basename(os.path.realpath(dev_node))
        if resolved != name or resolved.startswith("mmcblk") or resolved.startswith("loop"):
            raise BootDeviceRefused(dev_node)


def _normalize_mount_point(mount_point: str) -> str:
    if not mount_point or not mount_point.startswith("/"):
        raise BootDeviceRefused("refused mount point")
    normalized = os.path.normpath(mount_point)
    if normalized in FORBIDDEN_MOUNT_POINTS or normalized.startswith(OS_CARD_MOUNT_POINT + "/"):
        raise BootDeviceRefused(normalized)
    return normalized


class CmdResult:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def subprocess_runner(argv: list[str]) -> CmdResult:
    completed = subprocess.run(argv, capture_output=True, text=True)
    return CmdResult(completed.returncode, completed.stdout, completed.stderr)


def _mount_options(read_only: bool) -> str:
    # Import must not dirty the filesystem. Export uses sync so writes hit the card.
    if read_only:
        return "ro,noatime"
    return "sync,noatime"


class MountedBackup:
    def __init__(self, mount_point: str) -> None:
        self.mount_point = mount_point

    def list_backup_files(self) -> list[str]:
        names = []
        for name in sorted(os.listdir(self.mount_point)):
            if name.startswith(".") or not name.endswith(".ssenc"):
                continue
            path = os.path.join(self.mount_point, name)
            if os.path.isfile(path):
                names.append(name)
        return names

    def read_backup_file(self, filename: str, max_bytes: int) -> bytes:
        path = _safe_child(self.mount_point, filename)
        size = os.path.getsize(path)
        if size <= 0 or size > max_bytes:
            raise BackupIOError("backup file size is not valid")
        with open(path, "rb") as handle:
            data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise BackupIOError("backup file size is not valid")
        return data

    def write_backup_file(self, filename: str, data: bytes) -> str:
        filename = _unique_filename(self.mount_point, filename)
        final_path = _safe_child(self.mount_point, filename)
        temporary = final_path + ".partial"
        try:
            with open(temporary, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, final_path)
            directory = os.open(self.mount_point, os.O_RDONLY)
            try:
                try:
                    os.fsync(directory)
                except OSError as exc:
                    # Some FAT drivers reject directory fsync. sync(2) below still runs.
                    logger.warning("directory fsync failed: %s", exc)
            finally:
                os.close(directory)
            os.sync()
        except Exception:
            try:
                if os.path.exists(temporary):
                    os.remove(temporary)
            except OSError:
                pass
            raise
        return filename


def _safe_child(mount_point: str, filename: str) -> str:
    if not filename or filename != os.path.basename(filename) or filename.startswith("."):
        raise BackupIOError("refused backup filename")
    if "/" in filename or "\\" in filename:
        raise BackupIOError("refused backup filename")
    root = os.path.realpath(mount_point)
    path = os.path.join(root, filename)
    if os.path.dirname(path) != root:
        raise BackupIOError("refused backup filename")
    return path


def _unique_filename(mount_point: str, filename: str) -> str:
    if "." not in filename:
        raise BackupIOError("refused backup filename")
    stem, extension = filename.rsplit(".", 1)
    candidate = filename
    for suffix in range(2, 100):
        if not os.path.exists(os.path.join(mount_point, candidate)):
            return candidate
        candidate = f"{stem}-{suffix}.{extension}"
    raise BackupIOError("too many backup files on the card")


@contextmanager
def mounted_backup(
    dev_node: str,
    *,
    read_only: bool,
    source=None,
    runner=None,
    mount_point: str = BACKUP_MOUNT_POINT,
):
    """Mount ``dev_node`` only after a fresh boot-device check, then unmount."""
    source = source or SysfsBlockSource()
    runner = runner or subprocess_runner
    mount_point = _normalize_mount_point(mount_point)
    volume = assert_dev_node_eligible(dev_node, source)
    os.makedirs(mount_point, exist_ok=True)
    mounted = False
    try:
        result = runner(["mount", "-o", _mount_options(read_only), volume.dev_node, mount_point])
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "mount failed").strip()
            raise BackupIOError(detail)
        mounted = True
        observed = mounted_source(source.read_mounts(), mount_point)
        if observed != volume.dev_node:
            raise BootDeviceRefused(observed or "mount source mismatch")
        # Re-check after the mount in case the node was swapped for the boot card.
        assert_dev_node_eligible(observed, source)
        yield MountedBackup(mount_point)
    finally:
        if mounted:
            result = runner(["umount", mount_point])
            if result.returncode != 0:
                detail = (result.stderr or "umount failed").strip()
                raise NotSafeToRemove(detail or "unmount failed; do not remove the card")
            if mounted_source(source.read_mounts(), mount_point) is not None:
                raise NotSafeToRemove("card is still mounted; do not remove it")


def format_volume_label(volume: Volume) -> str:
    size = volume.size_bytes
    if size >= 1024 ** 3:
        pretty = f"{size / (1024 ** 3):.1f} GB"
    elif size >= 1024 ** 2:
        pretty = f"{size / (1024 ** 2):.0f} MB"
    elif size > 0:
        pretty = f"{size} B"
    else:
        pretty = "size unknown"
    return f"{volume.volume_name} ({pretty})"


def backup_filename(now=None) -> str:
    from datetime import datetime, timezone
    moment = now or datetime.now(timezone.utc)
    return moment.strftime("seedsigner-backup-%Y%m%dT%H%M%SZ.ssenc")
